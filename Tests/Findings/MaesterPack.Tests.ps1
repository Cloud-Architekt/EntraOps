#Requires -Modules Pester

BeforeDiscovery {
    # Test-MtPack exists from Maester 3.0 on (the version that introduced packs).
    $script:MaesterWithPacks = @(Get-Module -ListAvailable -Name Maester | Where-Object { $_.Version -ge [version]'3.0' }).Count -gt 0
    # Integrations/Maester is a distribution-only build source for the pack repository and is not an
    # update target, so a deployment updated by Update-EntraOps receives these tests without it.
    $script:MaesterPackSource = Test-Path -LiteralPath (Join-Path $PSScriptRoot '../../Integrations/Maester/Build-EntraOpsMaesterPack.ps1')
}

Describe 'EntraOps Maester Pack' -Skip:(-not $script:MaesterPackSource) {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:BuildScript = Join-Path $script:TestRepositoryRoot 'Integrations/Maester/Build-EntraOpsMaesterPack.ps1'
        $env:ENTRAOPS_NOWELCOME = '1'
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
        $script:Rules = @(Get-EntraOpsFindingRule)

        # The pack is generated into the pack repository (Cloud-Architekt/EntraOps-MaesterPack); here into TestDrive.
        $script:PackRoot = Join-Path $TestDrive 'pack'
        New-Item -ItemType Directory -Path (Join-Path $script:PackRoot 'assets') -Force | Out-Null
        '{}' | Set-Content -LiteralPath (Join-Path $script:PackRoot 'maester-pack.guide.json')
        [System.IO.File]::WriteAllBytes((Join-Path $script:PackRoot 'assets/banner.png'), [byte[]](0x89, 0x50, 0x4E, 0x47))
        & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath $script:PackRoot 6> $null
        $script:Manifest = Get-Content -LiteralPath (Join-Path $script:PackRoot 'maester-pack.json') -Raw | ConvertFrom-Json
    }

    It 'keeps the identity that Maester requires to stay the same for every release' {
        $script:Manifest.Id | Should -Be 'cloud-architekt.entraops'
        $script:Manifest.Guid | Should -Be '01964975-3423-4c3e-a3a0-b2510e0d6e39'
        $script:Manifest.Code | Should -Be 'EOPS'
        $script:Manifest.Publisher | Should -Be 'Cloud-Architekt'
        @($script:Manifest.Uses.Modules).Count | Should -Be 0 -Because 'the pack reads findings.json and needs no module'
    }

    It 'has the version of the EntraOps module and names the files of the pack repository' {
        $script:Manifest.Version | Should -Be (Get-Module EntraOps).Version.ToString()
        $script:Manifest.Homepage | Should -Be 'https://github.com/Cloud-Architekt/EntraOps-MaesterPack'
        $script:Manifest.Guide | Should -Be 'maester-pack.guide.json'
        $script:Manifest.Banner | Should -Be 'assets/banner.png'
        $Source = Get-Content -LiteralPath (Join-Path $script:PackRoot 'entraops-source.json') -Raw | ConvertFrom-Json
        $Source.Version | Should -Be $script:Manifest.Version
        $Source.Rules | Should -Be $script:Rules.Count
        (Get-Content -LiteralPath (Join-Path $script:PackRoot 'tests/suite.json') -Raw | ConvertFrom-Json).Id | Should -Be 'EOPS.Findings'
    }

    It 'names the GitHub repository of the commit it was generated from' {
        $Source = Get-Content -LiteralPath (Join-Path $script:PackRoot 'entraops-source.json') -Raw | ConvertFrom-Json
        $Remote = "$(git -C $script:TestRepositoryRoot remote get-url origin 2>$null)"
        # The origin of a clone (EntraOps, the Insiders repository or a fork), else EntraOps.
        $Expected = if ($Remote -match 'github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$') { "https://github.com/$($Matches[1])/$($Matches[2])" } else { 'https://github.com/Cloud-Architekt/EntraOps' }
        $Source.Repository | Should -Be $Expected
        $Source.Repository | Should -Not -Match '\.git$'
    }

    It 'leaves out the guide and banner that the pack repository does not have' {
        $Bare = Join-Path $TestDrive 'bare'
        & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath $Bare 6> $null
        $Manifest = Get-Content -LiteralPath (Join-Path $Bare 'maester-pack.json') -Raw | ConvertFrom-Json
        $Manifest.PSObject.Properties.Name | Should -Not -Contain 'Guide'
        $Manifest.PSObject.Properties.Name | Should -Not -Contain 'Banner'
    }

    It 'publishes the same pack from a staging repository with its own links' {
        $Staging = Join-Path $TestDrive 'staging'
        $PackUrl = 'https://github.com/contoso/EntraOps-Staging-MaesterPack'
        $SourceUrl = 'https://github.com/contoso/entraops-staging'
        & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath $Staging -PackRepository "$PackUrl/" -EntraOpsRepository $SourceUrl 6> $null
        $Manifest = Get-Content -LiteralPath (Join-Path $Staging 'maester-pack.json') -Raw | ConvertFrom-Json
        # The identity of the pack and its test IDs stay the same, so Update-MtPack moves between staging and release.
        foreach ($Field in 'Id', 'Guid', 'Code', 'Publisher', 'Version') { $Manifest.$Field | Should -Be $script:Manifest.$Field }
        $Manifest.Homepage | Should -Be $PackUrl
        $Manifest.Support | Should -Be "$PackUrl/issues"
        $Manifest.SecurityContact | Should -Be "$PackUrl/security/policy"
        (Get-Content -LiteralPath (Join-Path $Staging 'tests/suite.json') -Raw | ConvertFrom-Json).HelpUrlTemplate | Should -Be "$PackUrl/blob/main/tests/Test.{Id}.md"
        $Rule = $script:Rules[0]
        $Test = Get-Content -LiteralPath (Join-Path $Staging "tests/Test.$($Rule.MaesterTestId).ps1") -Raw
        $Test | Should -Match "HelpUrl\s+=\s+'$([regex]::Escape("$PackUrl/blob/main/tests/Test.$($Rule.MaesterTestId).md"))'"
        $Test | Should -Match 'Generated by Build-EntraOpsMaesterPack\.ps1 of contoso/entraops-staging '
        $Test | Should -Not -Match 'Cloud-Architekt/EntraOps-MaesterPack'
        Get-Content -LiteralPath (Join-Path $Staging "tests/Test.$($Rule.MaesterTestId).md") -Raw | Should -Match ([regex]::Escape("$SourceUrl/blob/main/EntraOps/Private/Findings/FindingRules.json"))
        @(Get-ChildItem -LiteralPath (Join-Path $Staging 'tests') -Filter 'Test.MP.*.ps1').Name | Should -Be @(Get-ChildItem -LiteralPath (Join-Path $script:PackRoot 'tests') -Filter 'Test.MP.*.ps1').Name
    }

    It 'accepts only GitHub repositories as pack and EntraOps repository' {
        { & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath (Join-Path $TestDrive 'invalid') -PackRepository 'https://example.com/pack' 6> $null } | Should -Throw '*PackRepository*'
        { & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath (Join-Path $TestDrive 'invalid') -EntraOpsRepository 'Cloud-Architekt/EntraOps' 6> $null } | Should -Throw '*EntraOpsRepository*'
    }

    It 'has one test per finding rule with its author and help link' {
        foreach ($Rule in $script:Rules) {
            $Test = Join-Path $script:PackRoot "tests/Test.$($Rule.MaesterTestId).ps1"
            $Test | Should -Exist
            Join-Path $script:PackRoot "tests/Test.$($Rule.MaesterTestId).md" | Should -Exist
            $Content = Get-Content -LiteralPath $Test -Raw
            $Content | Should -Match "Id\s+=\s+'$([regex]::Escape($Rule.MaesterTestId))'"
            $Content | Should -Match "Author\s+=\s+'Cloud-Architekt'"
            $Content | Should -Match "HelpUrl\s+=\s+'https://github\.com/Cloud-Architekt/EntraOps-MaesterPack/blob/main/tests/Test\.$([regex]::Escape($Rule.MaesterTestId))\.md'"
            $Content | Should -Match "EntraOps rule $([regex]::Escape($Rule.Id)) \($($Rule.Area)\.$($Rule.Key)\)"
        }
        @(Get-ChildItem -LiteralPath (Join-Path $script:PackRoot 'tests') -Filter 'Test.MP.*.ps1').Count | Should -Be $script:Rules.Count
    }

    It 'copies the helpers of the template' {
        # The build writes every file with LF line endings and a single trailing newline.
        $Template = (Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'Integrations/Maester/Template/helpers/EntraOpsFindings.ps1') -Raw).Replace("`r`n", "`n").TrimEnd("`n") + "`n"
        Get-Content -LiteralPath (Join-Path $script:PackRoot 'helpers/EntraOpsFindings.ps1') -Raw | Should -BeExactly $Template
    }

    It 'generates the same pack again over its own output' {
        $Before = @(Get-ChildItem -LiteralPath $script:PackRoot -File -Recurse | ForEach-Object { "$([System.IO.Path]::GetRelativePath($script:PackRoot, $_.FullName))|$((Get-FileHash -LiteralPath $_.FullName).Hash)" } | Sort-Object)
        & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath $script:PackRoot 6> $null
        @(Get-ChildItem -LiteralPath $script:PackRoot -File -Recurse | ForEach-Object { "$([System.IO.Path]::GetRelativePath($script:PackRoot, $_.FullName))|$((Get-FileHash -LiteralPath $_.FullName).Hash)" } | Sort-Object) | Should -Be $Before
    }

    It 'refuses to change or remove a test of the pack repository' {
        $Changed = Join-Path $TestDrive 'changed'
        Copy-Item -LiteralPath $script:PackRoot -Destination $Changed -Recurse
        $Test = Join-Path $Changed 'tests/Test.MP.EOPS.1001.ps1'
        (Get-Content -LiteralPath $Test -Raw).Replace('(TierBreach.tier0Breach)', '(TierBreach.renamedRule)') | Set-Content -LiteralPath $Test
        { & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath $Changed 6> $null } | Should -Throw '*Test.MP.EOPS.1001.ps1 tests TierBreach.renamedRule*'

        $Removed = Join-Path $TestDrive 'removed'
        Copy-Item -LiteralPath $script:PackRoot -Destination $Removed -Recurse
        (Get-Content -LiteralPath (Join-Path $Removed 'tests/Test.MP.EOPS.1001.ps1') -Raw).Replace('EO.1001', 'EO.1999') | Set-Content -LiteralPath (Join-Path $Removed 'tests/Test.MP.EOPS.1999.ps1')
        { & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath $Removed 6> $null } | Should -Throw '*rule EO.1999, which is no longer in the catalog*'
    }

    It 'holds only function definitions in every script' {
        foreach ($File in Get-ChildItem -LiteralPath $script:PackRoot -Filter '*.ps1' -File -Recurse) {
            $Tokens = $null; $Errors = $null
            $Ast = [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$Tokens, [ref]$Errors)
            $Errors | Should -BeNullOrEmpty
            foreach ($Statement in $Ast.EndBlock.Statements) {
                $Statement | Should -BeOfType ([System.Management.Automation.Language.FunctionDefinitionAst]) -Because "Maester refuses code outside a function ($($File.Name))"
            }
        }
    }

    It 'passes the checks of Install-MtPack' -Skip:(-not $script:MaesterWithPacks) {
        $Bare = Join-Path $TestDrive 'checked'
        & $script:BuildScript -RepoRoot $script:TestRepositoryRoot -OutputPath $Bare 6> $null
        $Check = pwsh -NoProfile -NonInteractive -Command "Import-Module Maester -MinimumVersion 3.0; Test-MtPack '$Bare' | ConvertTo-Json -Depth 5" | ConvertFrom-Json
        $Check.IsValid | Should -BeTrue
        $Check.Risk | Should -Be 'Low'
    }

    It 'rates the remediation of failing rules only' {
        $Failing = Get-Content -LiteralPath (Join-Path $script:PackRoot 'tests/Test.MP.EOPS.1001.ps1') -Raw
        $Failing | Should -Match "UserImpact\s+=\s+'Medium',"
        $Failing | Should -Match "ImplementationCost\s+=\s+'Medium',"
        $Failing | Should -Not -Match 'Lifecycle'
        $Investigate = Get-Content -LiteralPath (Join-Path $script:PackRoot 'tests/Test.MP.EOPS.2004.ps1') -Raw
        $Investigate | Should -Not -Match 'UserImpact|ImplementationCost'
    }

    It 'records the new rules of a release in the lock file and marks deprecated rules' {
        $Repo = Join-Path $TestDrive 'release-repo'
        New-Item -ItemType Directory -Path $Repo | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOps') -Destination $Repo -Recurse
        $LockPath = Join-Path $Repo 'EntraOps/Private/Findings/FindingRules.lock.json'
        $Lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
        $Lock.rules = @($Lock.rules | Where-Object Id -ne 'EO.8003')
        $Lock | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $LockPath
        $CatalogPath = Join-Path $Repo 'EntraOps/Private/Findings/FindingRules.json'
        $Catalog = Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json
        ($Catalog.rules | Where-Object Id -eq 'EO.8002') | Add-Member -NotePropertyName Lifecycle -NotePropertyValue 'Deprecated'
        $Catalog | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $CatalogPath
        # Separate process: the build imports the module copy into the session.
        pwsh -NoProfile -NonInteractive -File $script:BuildScript -RepoRoot $Repo -OutputPath (Join-Path $TestDrive 'release-pack') -Version '9.9.9' -Release 6> $null
        $LASTEXITCODE | Should -Be 0
        $Released = (Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json).rules
        @($Released).Count | Should -Be $script:Rules.Count
        ($Released | Where-Object Id -eq 'EO.8003').Since | Should -Be '9.9.9'
        ($Released | Where-Object Id -eq 'EO.8001').Since | Should -Not -Be '9.9.9'
        @($Released.Id) | Should -Be @($Released.Id | Sort-Object)
        Get-Content -LiteralPath (Join-Path $TestDrive 'release-pack/tests/Test.MP.EOPS.8002.ps1') -Raw | Should -Match "Lifecycle\s+=\s+'Deprecated',"
    }

    Context 'Test-EntraOpsPackFinding' {
        BeforeAll {
            . (Join-Path $script:TestRepositoryRoot 'Integrations/Maester/Template/helpers/EntraOpsFindings.ps1')
            # Stand-ins for the Maester commands the helpers call.
            function Get-MtSetting { param($Name, $Default) if ($script:Settings.ContainsKey($Name)) { $script:Settings[$Name] } else { $Default } }
            function Add-MtTestResultDetail { param($Result, $SkippedBecause, $SkippedCustomReason, $GraphObjects, [switch]$Investigate) $script:Detail = [pscustomobject]@{ Result = $Result; SkippedBecause = $SkippedBecause; SkippedCustomReason = $SkippedCustomReason; GraphObjects = @($GraphObjects | Where-Object { $_ }); Investigate = $Investigate.IsPresent } }
            function Get-MgContext { $script:GraphContext }

            function Save-TestFindings([object[]]$Rules, [string]$TenantId = 'tenant-1', [datetime]$GeneratedAt = (Get-Date).ToUniversalTime(), [string]$Folder) {
                $UseSetting = [string]::IsNullOrWhiteSpace($Folder)
                if ($UseSetting) { $Folder = Join-Path $TestDrive ([guid]::NewGuid()) }
                New-Item -ItemType Directory -Path $Folder -Force | Out-Null
                [ordered]@{ SchemaVersion = '1.0'; GeneratedAt = $GeneratedAt.ToString('o'); Generator = @{ Name = 'EntraOps'; Version = '1.2.0' }; TenantId = $TenantId; Rules = $Rules } |
                    ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Folder 'findings.json')
                $script:Settings = if ($UseSetting) { @{ 'EntraOps.FindingsPath' = $Folder } } else { @{} }
            }
            $script:PreviousEntraOpsRoot = $env:ENTRAOPS_ROOT
        }

        AfterAll {
            $env:ENTRAOPS_ROOT = $script:PreviousEntraOpsRoot
        }

        BeforeEach {
            $script:Detail = $null
            $script:GraphContext = $null
            $script:EntraOpsPackFindingCache = $null
            # No results in the default locations: an empty ENTRAOPS_ROOT, home and current folder.
            $script:Empty = Join-Path $TestDrive "empty-$([guid]::NewGuid())"
            New-Item -ItemType Directory -Path $script:Empty | Out-Null
            $env:ENTRAOPS_ROOT = $null
            Set-Variable -Name HOME -Value $script:Empty -Force
            Push-Location -LiteralPath $script:Empty
        }

        AfterEach {
            Pop-Location
        }

        It 'fails with a table of the affected objects' {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Failed'; EvaluatedCount = 3; FailedCount = 1; Results = @(@{ Instance = @{ DisplayName = 'Admin | <b>A</b>'; ObjectType = 'user' }; Message = 'Object tier below role assignments.' }) })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match 'EntraOps found 1 affected instance of 3 evaluated'
            # The object in bold, with its findings as a list below it.
            $script:Detail.Result | Should -Match ([regex]::Escape("`n| Object | Finding |`n| --- | --- |`n| 👤 **Admin \| &lt;b&gt;A&lt;/b&gt;** | Object tier below role assignments. |"))
            # Without an object ID there is nothing to link, and without the reports no report links.
            $script:Detail.Result | Should -Not -Match '\]\(https://'
            $script:Detail.Result | Should -Not -Match '↗'
            $script:Detail.GraphObjects | Should -BeNullOrEmpty
        }

        It 'links the objects to the Microsoft Entra admin center and the EntraOps reports next to the results' {
            $Root = Join-Path $TestDrive "reports-$([guid]::NewGuid())"
            New-Item -ItemType Directory -Path (Join-Path $Root 'Reports/PrivilegedAssets') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'Reports/PrivilegedAssets/index.html') -Value '<html></html>'
            $UserId = 'aaaaaaaa-1111-1111-1111-111111111111'
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Area = 'TierBreach'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 2; Results = @(
                        @{ Instance = @{ ObjectId = $UserId; DisplayName = 'Admin [1]'; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }
                            Evidence = @{ Role = 'Owner'; Service = 'Billing'; ScopeId = '/providers/Microsoft.Management/managementGroups/root'; ScopeName = 'root'; PathIds = @('path-1'); AssignmentInstanceId = 'EO_RA_1'; PimAssignmentType = 'Eligible' }
                            Message = "Management Plane object 'Admin [1]' reaches 'Billing' through 'Owner' at 'root'." }
                        @{ Instance = @{ ObjectId = $UserId; DisplayName = 'Admin [1]'; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }
                            Evidence = @{ Role = 'Contributor'; Service = 'Billing'; ScopeId = '/subscriptions/1'; PathIds = @('path-2'); AssignmentInstanceId = 'EO_RA_2'; PimAssignmentType = 'Permanent' }
                            Message = "Management Plane object 'Admin [1]' reaches 'Billing' through 'Contributor'." }
                    ) }) -Folder (Join-Path $Root 'Reports/Findings/data')
            $script:Settings['EntraOps.FindingsPath'] = Join-Path $Root 'Reports/Findings/data'
            $Base = (($Root -replace '\\', '/').Split('/') | ForEach-Object { if ($_ -match '^[A-Za-z]:$') { $_ } else { [uri]::EscapeDataString($_) } }) -join '/'
            if (-not $Base.StartsWith('/')) { $Base = "/$Base" }

            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match 'EntraOps found 2 affected instances of 9 evaluated, on 1 object\.'
            # The object once, with the number of its findings and the links that all of them share.
            $script:Detail.Result | Should -Match ([regex]::Escape("☁️ 👤 **[Admin \[1\]](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/$UserId)** · 2 findings · ↗ [EAM Dashboard]($Base/Reports/EamDashboard/index.html#asset=$UserId `"EntraOps EAM Dashboard`") · [Access path]($Base/Reports/AccessPathMap/index.html#node=$($UserId.ToUpperInvariant()) `"EntraOps Access Path Map`") | Reaches Billing through Owner at root."))
            # The evidence that the message does not name (the PIM assignment type and the scope) and the links of each finding.
            $script:Detail.Result | Should -Match ([regex]::Escape("at root. — *⏳ eligible* ↗ [Tier breach]($Base/Reports/TierBreachAnalyzer/index.html#sel=$([uri]::EscapeDataString("$UserId||Owner||Billing||/providers/Microsoft.Management/managementGroups/root||path-1")) `"EntraOps Tier Breach Analyzer`") · [Assignment]($Base/Reports/EamDashboard/index.html#assignment=EO_RA_1 `"EntraOps EAM Dashboard assignment`") |`n"))
            $script:Detail.Result | Should -Match ([regex]::Escape("`n|  | Reaches Billing through Contributor. — *📌 permanent · scope /subscriptions/1* ↗ [Tier breach]("))
            $script:Detail.Result | Should -Not -Match '↳|Open in EntraOps'
            $script:Detail.Result | Should -Match ([regex]::Escape("🔎 [Open EO.1001 in the EntraOps Findings view]($Base/Reports/PrivilegedAssets/index.html?view=findings#rule=EO.1001)"))
            # The legend names the icons of this list only.
            $script:Detail.Result | Should -Match ([regex]::Escape('_☁️ Management Plane · 👤 user_'))
            # The object of both results, once, for the affected objects of Maester.
            $script:Detail.GraphObjects.Count | Should -Be 1
            $script:Detail.GraphObjects[0].id | Should -Be $UserId
            $script:Detail.GraphObjects[0].'@odata.type' | Should -Be '#microsoft.graph.user'

            # A published location, or no report links at all.
            $script:Settings['EntraOps.ReportsPath'] = 'https://reports.contoso.com/entraops/'
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('(https://reports.contoso.com/entraops/EamDashboard/index.html#asset='))
            $script:Settings['EntraOps.ReportsPath'] = 'None'
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Not -Match 'EntraOps reports \||Findings view'
            $script:Detail.Result | Should -Match 'https://entra\.microsoft\.com/'
        }

        It 'links the reports of PIM role settings, access package policies and Conditional Access policies' {
            Save-TestFindings @(
                @{ RuleId = 'EO.3004'; Area = 'PimRequestFlow'; Status = 'Failed'; EvaluatedCount = 1; FailedCount = 1; Results = @(@{ Instance = @{ Id = 'role-1.eligibleAssignment'; ObjectId = 'role-1'; DisplayName = 'Global Administrator'; ObjectType = 'roleSetting'; AdminTierLevelName = 'ControlPlane' }; Evidence = @{ FlowId = 'role-1|eligibleAssignment' }; Message = 'Permanent.' }) }
                @{ RuleId = 'EO.6005'; Area = 'TenantGovernance'; Status = 'Failed'; EvaluatedCount = 1; FailedCount = 1; Results = @(@{ Instance = @{ ObjectId = 'policy-1'; DisplayName = 'Package / Policy'; ObjectType = 'accessPackageAssignmentPolicy' }; Evidence = @{ AccessPackageId = 'bbbbbbbb-2222-2222-2222-222222222222'; AccessPackageName = 'Package' }; Message = 'No expiry.' }) }
                @{ RuleId = 'EO.4003'; Area = 'TenantGovernance'; Status = 'Failed'; EvaluatedCount = 1; FailedCount = 1; Results = @(@{ Instance = @{ ObjectId = 'cccccccc-3333-3333-3333-333333333333'; DisplayName = 'CA 100'; ObjectType = 'conditionalAccessPolicy' }; Message = 'Excludes Control Plane users.' }) }
            )
            $script:Settings['EntraOps.ReportsPath'] = 'https://r.contoso.com'
            Test-EntraOpsPackFinding -RuleId 'EO.3004' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape("| 🔐 ⏱️ **Global Administrator** | Permanent. ↗ [PIM flow](https://r.contoso.com/PimRequestFlow/index.html#flow=role-1%7CeligibleAssignment `"EntraOps PIM Request Flow`") · [Configuration](https://r.contoso.com/ConfigurationAnalyzer/index.html#object=microsoft.entra.rolesetting%7Crole-1 `"EntraOps Configuration Analyzer`") |"))
            $script:Detail.GraphObjects | Should -BeNullOrEmpty
            Test-EntraOpsPackFinding -RuleId 'EO.6005' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('| 📦 **[Package](https://entra.microsoft.com/#view/Microsoft_Azure_ELMAdmin/EntitlementMenuBlade/~/overview/entitlementId/bbbbbbbb-2222-2222-2222-222222222222)** / Policy | No expiry. ↗'))
            $script:Detail.Result | Should -Match ([regex]::Escape('[Package flow](https://r.contoso.com/AccessPackageFlow/index.html#flow=policy-1 "EntraOps Access Package Flow")'))
            Test-EntraOpsPackFinding -RuleId 'EO.4003' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('🛡️ **[CA 100](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/cccccccc-3333-3333-3333-333333333333)**'))
            $script:Detail.Result | Should -Match ([regex]::Escape('[CA analysis](https://r.contoso.com/ConditionalAccessAnalysis/index.html#flow=cccccccc-3333-3333-3333-333333333333 "EntraOps Conditional Access Analysis")'))
            $script:Detail.GraphObjects[0].'@odata.type' | Should -Be '#microsoft.graph.conditionalAccessPolicy'
        }

        It 'tells objects with the same name apart by their ID' {
            Save-TestFindings @(@{ RuleId = 'EO.2001'; Status = 'Failed'; EvaluatedCount = 2; FailedCount = 2; Results = @(
                        @{ Instance = @{ ObjectId = 'dddddddd-4444-4444-4444-444444444444'; DisplayName = 'Operator'; ObjectType = 'serviceprincipal' }; Message = 'Unclassified.' }
                        @{ Instance = @{ ObjectId = 'eeeeeeee-5555-5555-5555-555555555555'; DisplayName = 'Operator'; ObjectType = 'serviceprincipal' }; Message = 'Unclassified.' }
                    ) })
            Test-EntraOpsPackFinding -RuleId 'EO.2001' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('[Operator (dddddddd)](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/dddddddd-4444-4444-4444-444444444444)'))
            $script:Detail.Result | Should -Match ([regex]::Escape('[Operator (eeeeeeee)]'))
            $script:Detail.GraphObjects.Count | Should -Be 2
        }

        It 'shortens a long name in the middle and keeps the full name as the tooltip of its link' {
            Save-TestFindings @(@{ RuleId = 'EO.2001'; Status = 'Failed'; EvaluatedCount = 1; FailedCount = 1; Results = @(
                        @{ Instance = @{ ObjectId = 'dddddddd-4444-4444-4444-444444444444'; DisplayName = 'CloudPosture/securityOperators/DefenderCSPMSecurityOperator'; ObjectType = 'serviceprincipal' }; Message = 'Unclassified.' }
                    ) })
            Test-EntraOpsPackFinding -RuleId 'EO.2001' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('**[CloudPosture/securityOperato…ityOperator](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/dddddddd-4444-4444-4444-444444444444 "CloudPosture/securityOperators/DefenderCSPMSecurityOperator")**'))
            # Maester records the object with its full name.
            $script:Detail.GraphObjects[0].displayName | Should -Be 'CloudPosture/securityOperators/DefenderCSPMSecurityOperator'
        }

        It 'keeps the reason of a rule that does not apply and lists the objects of a rule skipped for unclassified objects' {
            Save-TestFindings @(
                @{ RuleId = 'EO.3012'; Status = 'Skipped'; ReasonCode = 'NotApplicable'; Reason = 'All roles allow permanent eligible assignments (reported by EO.3004).'; Results = @() }
                @{ RuleId = 'EO.1003'; Area = 'TierBreach'; Status = 'Skipped'; ReasonCode = 'Unclassified'; Reason = 'Only unclassified objects are affected: 1 unclassified object(s) with 2 affected role assignments.'; Results = @(); UnclassifiedCount = 2; UnclassifiedResults = @(
                        @{ Instance = @{ ObjectId = 'ffffffff-6666-6666-6666-666666666666'; DisplayName = 'App'; ObjectType = 'serviceprincipal'; AdminTierLevelName = 'Unclassified' }; Message = 'Reaches A.' }
                        @{ Instance = @{ ObjectId = 'ffffffff-6666-6666-6666-666666666666'; DisplayName = 'App'; ObjectType = 'serviceprincipal'; AdminTierLevelName = 'Unclassified' }; Message = 'Reaches B.' }
                    ) }
            )
            Test-EntraOpsPackFinding -RuleId 'EO.3012' | Should -BeNullOrEmpty
            $script:Detail.SkippedBecause | Should -Be 'NotApplicable'
            $script:Detail.Result | Should -Match 'because it does not apply: All roles allow permanent eligible assignments \(reported by EO\.3004\)\.'
            Test-EntraOpsPackFinding -RuleId 'EO.1003' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match '^EntraOps did not report rule EO.1003: Only unclassified objects'
            $script:Detail.Result | Should -Match ([regex]::Escape('| ❔ 🤖 **[App](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/ffffffff-6666-6666-6666-666666666666)** | 2 findings, for example: Reaches A. |'))
        }

        It 'lists the findings by object, at most five per object, so other objects are not hidden' {
            $Results = @(
                foreach ($Index in 1..12) { @{ Instance = @{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Big App'; ObjectType = 'serviceprincipal' }; Message = "Permission $Index." } }
                @{ Instance = @{ ObjectId = '22222222-2222-2222-2222-222222222222'; DisplayName = 'Small App'; ObjectType = 'serviceprincipal' }; Message = 'Permission A.' }
                @{ Instance = @{ ObjectId = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Big App'; ObjectType = 'serviceprincipal' }; Message = 'Permission 13.' }
            )
            Save-TestFindings @(@{ RuleId = 'EO.5005'; Area = 'PrivilegedEAM'; Status = 'Failed'; EvaluatedCount = 20; FailedCount = 14; Results = $Results })
            Test-EntraOpsPackFinding -RuleId 'EO.5005' | Should -BeFalse
            $script:Detail.Result | Should -Match '(?m)^\|  \| Permission 5\. \|$'
            $script:Detail.Result | Should -Not -Match 'Permission 6\.'
            $script:Detail.Result | Should -Match '\.\.\. and 8 more findings of this object\.'
            $script:Detail.Result | Should -Match 'Permission A\.'
            # The objects keep the order of their first result: Big App before Small App.
            $script:Detail.Result.IndexOf('Big App') | Should -BeLessThan $script:Detail.Result.IndexOf('Small App')

            # The findings of the list are limited: the rest is counted by findings and objects.
            Test-EntraOpsPackFinding -RuleId 'EO.5005' -MaxRows 3 | Should -BeFalse
            $script:Detail.Result | Should -Match '\.\.\. and 11 more findings on 1 more object\. The EntraOps reports list all of them\.'
        }

        It 'shows the settings of a rule and what its finding exceptions need' {
            $Soon = (Get-Date).ToUniversalTime().AddDays(10).ToString('yyyy-MM-dd')
            Save-TestFindings @(@{ RuleId = 'EO.3013'; Status = 'Failed'; EvaluatedCount = 4; FailedCount = 1; AcceptedCount = 1; Parameters = @{ MaxHours = 4; EmergencyAccessAccounts = @() }
                    Results = @(@{ Instance = @{ ObjectId = 'role-1'; DisplayName = 'Global Administrator'; ObjectType = 'roleSetting' }; Message = 'Activated for 8 hours.' })
                    AcceptedResults = @(@{ Instance = @{ ObjectId = 'role-2'; DisplayName = 'Security Administrator'; ObjectType = 'roleSetting' }; Message = 'Activated for 6 hours.'; Exception = @{ State = 'RiskAccepted'; ExpiresOn = $Soon; Reference = 'CHG-7'; Justification = 'Migration'; AcceptedBy = 'Alex'; AcceptedOn = '2026-10-01' } })
                    Exceptions = @(
                        @{ DisplayName = 'Security Administrator'; State = 'RiskAccepted'; Status = 'Active'; MatchedCount = 1 }
                        @{ DisplayName = 'Old Role'; State = 'RiskAccepted'; Status = 'Expired'; MatchedCount = 1 }
                        @{ DisplayName = 'Gone Role'; State = 'Dismissed'; Status = 'Stale'; MatchedCount = 0 }
                    )
                })
            Test-EntraOpsPackFinding -RuleId 'EO.3013' | Should -BeFalse
            $script:Detail.Result | Should -Match 'EntraOps settings of this check \(EntraOpsConfig\.json\): EmergencyAccessAccounts: none; MaxHours: 4\.|EntraOps settings of this check \(EntraOpsConfig\.json\): MaxHours: 4; EmergencyAccessAccounts: none\.'
            $script:Detail.Result | Should -Match '1 finding exception expired, so their findings count again: Old Role\.'
            $script:Detail.Result | Should -Match '1 finding exception matches no finding anymore: Gone Role\. Remove them'
            $script:Detail.Result | Should -Match ([regex]::Escape("1 risk acceptance expires within 30 days: Security Administrator ($Soon)."))
            $script:Detail.Result | Should -Match ([regex]::Escape("| ⏱️ **Security Administrator** | Activated for 6 hours. ⚖️ Risk accepted until $Soon · CHG-7 · Migration · by Alex on 2026-10-01 |"))
        }

        It 'reports the results of a rule that asks for a review as Investigate' {
            Save-TestFindings @(
                @{ RuleId = 'EO.2004'; Investigate = $true; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 1; Results = @(@{ Instance = @{ ObjectId = 'r1'; DisplayName = 'NetOps'; ObjectType = 'roleDefinition' }; Message = 'Custom role with Control Plane permissions.' }) }
                @{ RuleId = 'EO.2001'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 1; Results = @(@{ Instance = @{ ObjectId = 'o1'; DisplayName = 'App'; ObjectType = 'serviceprincipal' }; Message = 'Unclassified.' }) }
            )
            Test-EntraOpsPackFinding -RuleId 'EO.2004' | Should -BeTrue
            $script:Detail.Investigate | Should -BeTrue
            $script:Detail.Result | Should -Match 'EntraOps found 1 instance to investigate of 9 evaluated\.'
            # Without the flag (and in results of EntraOps versions without it), findings fail the test.
            Test-EntraOpsPackFinding -RuleId 'EO.2001' | Should -BeFalse
            $script:Detail.Investigate | Should -BeFalse
        }

        It 'shows the names that a message quotes as plain text, but keeps apostrophes in words' {
            ConvertTo-EntraOpsPackFindingText (Split-EntraOpsPackMessage "Owns 'CL1', 'Scotty's Mac' (4) and 'a | b'.") | Should -Be "Owns CL1, 'Scotty's Mac' (4) and a \| b."
            ConvertTo-EntraOpsPackFindingText (Split-EntraOpsPackMessage "Role 'Owner' at '*_root_*' via 'prg_Lab'.") | Should -Be 'Role **Owner** at \*\_root\_\* via prg_Lab.'
            (Split-EntraOpsPackMessage "Role 'Owner' at 'root'.").Names | Should -Be @('Owner', 'root')
            Get-EntraOpsPackIcon -TierKey 'ControlPlane' | Should -Be '🔐'
            Get-EntraOpsPackIcon -TierKey 'UserAccess' | Should -Be 'ℹ️'
            Get-EntraOpsPackIcon -TypeKey 'servicePrincipal' | Should -Be '🤖'
            Get-EntraOpsPackReportLabel 'EAM Dashboard assignment 2' | Should -Be 'Assignment 2'
            Get-EntraOpsPackReportLabel 'Tier Breach Analyzer' | Should -Be 'Tier breach'
        }

        It 'shows the detail of a result without the object and tier that the object column shows' {
            Save-TestFindings @(@{ RuleId = 'EO.4009'; Status = 'Failed'; EvaluatedCount = 2; FailedCount = 1; Results = @(
                        @{ Instance = @{ ObjectId = 'u1'; DisplayName = 'admAdeleV'; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }; Message = "Management Plane object 'admAdeleV' (user) is not linked to a work account."; Detail = 'Is not linked to a work account.' }
                    ) })
            Test-EntraOpsPackFinding -RuleId 'EO.4009' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape("| ☁️ 👤 **admAdeleV** | Is not linked to a work account. |"))
        }

        It 'removes the object and tier from the messages of results without Detail' {
            Save-TestFindings @(@{ RuleId = 'EO.4009'; Status = 'Failed'; EvaluatedCount = 3; FailedCount = 2; Results = @(
                        @{ Instance = @{ ObjectId = 'u1'; DisplayName = 'admAdeleV'; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }; Message = "Management Plane object 'admAdeleV' (user) is not linked to a work account." }
                        # Another tier than the one of the object: the message stays as it is.
                        @{ Instance = @{ ObjectId = 'u2'; DisplayName = 'admX'; ObjectType = 'user'; AdminTierLevelName = 'ControlPlane' }; Message = "Management Plane object 'admX' is not linked to a work account." }
                    ) })
            Test-EntraOpsPackFinding -RuleId 'EO.4009' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape("| ☁️ 👤 **admAdeleV** | Is not linked to a work account. |"))
            $script:Detail.Result | Should -Match ([regex]::Escape("| 🔐 👤 **admX** | **Management Plane** object admX is not linked to a work account. |"))
        }

        It 'shows findings of an object that differ in one name as one line, each name linked to its report' {
            $UserId = 'aaaaaaaa-1111-1111-1111-111111111111'
            $Result = {
                param($Scope, $Path)
                @{ Instance = @{ ObjectId = $UserId; DisplayName = 'Admin'; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }
                    Evidence = @{ Role = 'Contributor'; Service = 'Billing'; ScopeId = "/$Scope"; ScopeName = $Scope; PathIds = @($Path); AssignmentInstanceId = "EO_$Path"; PimAssignmentType = 'Eligible' }
                    Detail = "Reaches 'Billing' through the role 'Contributor' at '$Scope' via 'prg_A'."; Message = 'x' }
            }
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Area = 'TierBreach'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 4; Results = @(
                        (& $Result 'scope-a' 'p1'), (& $Result 'scope-b' 'p2'), (& $Result 'scope-b' 'p3')
                        @{ Instance = @{ ObjectId = $UserId; DisplayName = 'Admin'; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }; Evidence = @{ PimAssignmentType = 'Permanent' }; Detail = "Reaches 'Billing' through the role 'Owner' at 'scope-a' via 'prg_A'."; Message = 'y' }
                    ) })
            $script:Settings['EntraOps.ReportsPath'] = 'https://r.contoso.com'
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape("☁️ 👤 **[Admin](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/$UserId)** · 4 findings · ↗ [EAM Dashboard]"))
            $script:Detail.Result | Should -Match ([regex]::Escape(" | Reaches Billing through the role **Contributor** at [scope-a](https://r.contoso.com/TierBreachAnalyzer/index.html#sel=$([uri]::EscapeDataString("$UserId||Contributor||Billing||/scope-a||p1")) `"EntraOps Tier Breach Analyzer`") and [scope-b](https://r.contoso.com/TierBreachAnalyzer/index.html#sel=$([uri]::EscapeDataString("$UserId||Contributor||Billing||/scope-b||p2")) `"EntraOps Tier Breach Analyzer`") via prg_A. — *⏳ eligible* |`n"))
            # Another evidence is another line.
            $script:Detail.Result | Should -Match ([regex]::Escape("`n|  | Reaches Billing through the role **Owner** at scope-a via prg_A. — *📌 permanent* |"))
        }

        It 'shows a finding that several objects share once, with a table of these objects' {
            $Roles = @('AI Administrator', 'AI Reader', 'Application Administrator', 'Helpdesk Administrator')
            $Results = @(
                foreach ($Role in $Roles) { @{ Instance = @{ ObjectId = "role-$Role"; DisplayName = $Role; ObjectType = 'roleSetting'; AdminTierLevelName = 'ControlPlane' }; Evidence = @{ FlowId = "role-$Role|activation" }; Detail = 'Can be activated without approval.'; Message = 'x' } }
                @{ Instance = @{ ObjectId = 'role-x'; DisplayName = 'Security Reader'; ObjectType = 'roleSetting'; AdminTierLevelName = 'ControlPlane' }; Evidence = @{ FlowId = 'role-x|activation' }; Detail = 'Can be activated by anyone.'; Message = 'y' }
            )
            Save-TestFindings @(@{ RuleId = 'EO.3007'; Area = 'PimRequestFlow'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 5; Results = $Results })
            $script:Settings['EntraOps.ReportsPath'] = 'https://r.contoso.com'
            Test-EntraOpsPackFinding -RuleId 'EO.3007' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape("Can be activated without approval. — **4 PIM role settings:**`n`n| Object | Details |`n| --- | --- |`n| 🔐 ⏱️ **AI Administrator** | ↗ [PIM flow](https://r.contoso.com/PimRequestFlow/index.html#flow="))
            # The finding is not repeated in its rows; the finding of one object follows in a table of its own.
            ([regex]::Matches($script:Detail.Result, 'Can be activated without approval')).Count | Should -Be 1
            $script:Detail.Result | Should -Match ([regex]::Escape("**Other findings:**`n`n| Object | Finding |`n| --- | --- |`n| 🔐 ⏱️ **Security Reader** | Can be activated by anyone. ↗ [PIM flow]"))
        }

        It 'emphasizes the tiers and the role or permission of a finding, and shows IDs as code' {
            ConvertTo-EntraOpsPackFindingText (Split-EntraOpsPackMessage "Holds the Control Plane role 'Global Administrator' via 'Group A'.") | Should -Be 'Holds the **Control Plane** role **Global Administrator** via Group A.'
            ConvertTo-EntraOpsPackFindingText (Split-EntraOpsPackMessage "Service principal of the application of tenant aaaaaaaa-1111-1111-1111-111111111111 has Control Plane access.") | Should -Be 'Service principal of the application of tenant `aaaaaaaa-1111-1111-1111-111111111111` has **Control Plane** access.'
        }

        It 'lists classified objects first and says how many findings are on unclassified objects' {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 3; Results = @(
                        @{ Instance = @{ ObjectId = 'o1'; DisplayName = 'Unknown App'; ObjectType = 'serviceprincipal'; AdminTierLevelName = 'Unclassified' }; Detail = 'Reaches A.'; Message = 'x' }
                        @{ Instance = @{ ObjectId = 'o1'; DisplayName = 'Unknown App'; ObjectType = 'serviceprincipal'; AdminTierLevelName = 'Unclassified' }; Detail = 'Reaches B.'; Message = 'x' }
                        @{ Instance = @{ ObjectId = 'o2'; DisplayName = 'Known Admin'; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }; Detail = 'Reaches C.'; Message = 'x' }
                    ) })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match 'EntraOps found 3 affected instances of 9 evaluated, on 2 objects\.'
            $script:Detail.Result | Should -Match ([regex]::Escape('❔ 2 of them are on 1 unclassified object, listed last: classify this object first (MP.EOPS.2001), as its tier decides what applies to it.'))
            $script:Detail.Result.IndexOf('Known Admin') | Should -BeLessThan $script:Detail.Result.IndexOf('Unknown App')
        }

        It 'sends only the unclassified objects that EO.2001 reports to MP.EOPS.2001' {
            $Sp = { param($Id, $Name) @{ Instance = @{ ObjectId = $Id; DisplayName = $Name; ObjectType = 'serviceprincipal'; AdminTierLevelName = 'Unclassified' }; Detail = 'Has access.'; Message = 'x' } }
            Save-TestFindings @(
                @{ RuleId = 'EO.5005'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 3; Results = @((& $Sp 'o1' 'Custom App'), (& $Sp 'o2' 'Graph Explorer'), (& $Sp 'o3' 'Microsoft Intune PowerShell')) }
                # Microsoft first-party applications are not reported by EO.2001.
                @{ RuleId = 'EO.2001'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 1; Results = @((& $Sp 'o1' 'Custom App')) }
            )
            Test-EntraOpsPackFinding -RuleId 'EO.5005' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('❔ All of them are on 3 unclassified objects, listed last: classify the 1 that MP.EOPS.2001 reports first, as their tier decides what applies to them. The other 2 are not reported by MP.EOPS.2001 (for example service principals of Microsoft first-party applications, which Microsoft operates): review their access instead.'))
            # One finding on one unclassified object.
            Save-TestFindings @(@{ RuleId = 'EO.1004'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 1; Results = @((& $Sp 'o1' 'Custom App')) })
            Test-EntraOpsPackFinding -RuleId 'EO.1004' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('❔ It is on 1 unclassified object, listed last: classify this object first (MP.EOPS.2001), as its tier decides what applies to it.'))
            # The rules about principals of other tenants judge the role assignments, not the tier of the object: no advice to classify.
            foreach ($RuleId in 'EO.4002', 'EO.4010', 'EO.4011', 'EO.5001') {
                Save-TestFindings @(@{ RuleId = $RuleId; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 1; Results = @((& $Sp 'o1' 'Custom App')) })
                Test-EntraOpsPackFinding -RuleId $RuleId | Should -BeFalse
                $script:Detail.Result | Should -Not -Match 'unclassified object'
            }
        }

        It 'puts the text around several names of one line in the plural, with the roles or permissions in bold' {
            $Result = { param($Detail) @{ Instance = @{ ObjectId = 'o1'; DisplayName = 'App'; ObjectType = 'serviceprincipal'; AdminTierLevelName = 'ManagementPlane' }; Detail = $Detail; Message = 'x' } }
            Save-TestFindings @(@{ RuleId = 'EO.5005'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 2; Results = @(
                        (& $Result "Has the delegated Control Plane permission 'Group.ReadWrite.All' of 'Microsoft Graph'."), (& $Result "Has the delegated Control Plane permission 'User.ReadWrite.All' of 'Microsoft Graph'.")) })
            Test-EntraOpsPackFinding -RuleId 'EO.5005' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('Has the delegated **Control Plane** permissions **Group.ReadWrite.All** and **User.ReadWrite.All** of Microsoft Graph.'))
            Save-TestFindings @(@{ RuleId = 'EO.2002'; Status = 'Failed'; EvaluatedCount = 9; FailedCount = 2; Results = @(
                        (& $Result "'Zone.Read.All' (ResourceApps) has no tier classification."), (& $Result "'Access' (ResourceApps) has no tier classification.")) })
            Test-EntraOpsPackFinding -RuleId 'EO.2002' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('Zone.Read.All and Access (ResourceApps) have no tier classification.'))
        }

        It 'says that the principals of the Global Exclusion List are not covered, for the checks of the Privileged EAM data' {
            $Folder = Join-Path $TestDrive ([guid]::NewGuid())
            New-Item -ItemType Directory -Path $Folder -Force | Out-Null
            [ordered]@{
                SchemaVersion = '1.0'; GeneratedAt = (Get-Date).ToUniversalTime().ToString('o'); Generator = @{ Name = 'EntraOps'; Version = '1.2.0' }; TenantId = 'tenant-1'
                GlobalExclusions = @{ FilePath = './Classification/Global.json'; Count = 1; PrincipalIds = @('0000000a-0000-0000-0000-00000000000a') }
                Rules = @(
                    @{ RuleId = 'EO.1001'; Area = 'TierBreach'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; Results = @() }
                    @{ RuleId = 'EO.3004'; Area = 'PimRequestFlow'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; Results = @() }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Folder 'findings.json')
            $script:Settings = @{ 'EntraOps.FindingsPath' = $Folder }
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeTrue
            $script:Detail.Result | Should -Match ([regex]::Escape('1 principal of the Global Exclusion List of EntraOps (./Classification/Global.json) is not in the Privileged EAM data, so this check does not cover its privileged access.'))
            $script:EntraOpsPackFindingCache = $null
            Test-EntraOpsPackFinding -RuleId 'EO.3004' | Should -BeTrue
            $script:Detail.Result | Should -Not -Match 'Global Exclusion List'
        }

        It 'passes when no instance is affected' {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; Results = @() })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeTrue
        }

        It 'passes for dismissed instances and skips for risk-accepted ones without an open instance' {
            $accepted = { param($Name, $State, $ExpiresOn, $Reference) @{ Instance = @{ DisplayName = $Name; ObjectType = 'user' }; Status = $State; Exception = @{ State = $State; ExpiresOn = $ExpiresOn; Reference = $Reference } } }

            # Only false positives: the control is met.
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; AcceptedCount = 2; Results = @(); AcceptedResults = @((& $accepted 'App A' 'Dismissed'), (& $accepted 'App B' 'Dismissed')) })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeTrue
            $script:Detail.Result | Should -Match '2 affected instances are dismissed as false positives'

            # A risk-accepted instance: not met, but accepted - skipped with the accepted risks.
            $script:EntraOpsPackFindingCache = $null
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; AcceptedCount = 2; Results = @(); AcceptedResults = @((& $accepted 'Admin A' 'RiskAccepted' '2027-04-27' 'CHG-1'), (& $accepted 'App B' 'Dismissed')) })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedBecause | Should -Be 'Custom'
            $script:Detail.SkippedCustomReason | Should -Match '^Risk accepted in EntraOps: 1 affected instance of 3 evaluated, no open one \(Admin A \(until 2027-04-27, CHG-1\)\); 1 more dismissed'

            # Accepted instances without their exception count as risk accepted.
            $script:EntraOpsPackFindingCache = $null
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; AcceptedCount = 1; Results = @() })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'Risk accepted in EntraOps: 1 affected instance .+\(1 more\)'

            # Open instances fail the test; the accepted ones are named apart.
            $script:EntraOpsPackFindingCache = $null
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Failed'; EvaluatedCount = 3; FailedCount = 1; AcceptedCount = 2; Results = @(@{ Instance = @{ DisplayName = 'Admin'; ObjectType = 'user' }; Message = 'Breach.' }); AcceptedResults = @((& $accepted 'Admin A' 'RiskAccepted' '2027-04-27'), (& $accepted 'App B' 'Dismissed')) })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match '1 more instance is risk accepted in the EntraOps finding exceptions and listed apart: Admin A \(until 2027-04-27\)\.'
            $script:Detail.Result | Should -Match '1 more instance is dismissed as false positives'
        }

        It 'fails for a risk acceptance that expired after the evaluation' {
            $Yesterday = (Get-Date).ToUniversalTime().AddDays(-1).ToString('yyyy-MM-dd')
            $NextYear = (Get-Date).ToUniversalTime().AddYears(1).ToString('yyyy-MM-dd')
            $accepted = { param($Name, $ExpiresOn) @{ Instance = @{ DisplayName = $Name; ObjectType = 'user' }; Status = 'RiskAccepted'; Exception = @{ State = 'RiskAccepted'; ExpiresOn = $ExpiresOn; Reference = 'CHG-1' } } }
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; AcceptedCount = 2; Results = @(); AcceptedResults = @((& $accepted 'Admin A' $Yesterday), (& $accepted 'Admin B' $NextYear)) })

            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match '1 affected instance of 3 evaluated'
            $script:Detail.Result | Should -Match ([regex]::Escape("1 finding exception(s) expired after the evaluation, so their instances are open again: Admin A (expired $Yesterday)."))
            # The other acceptance still applies and is listed apart.
            $script:Detail.Result | Should -Match '1 more instance is risk accepted'
        }

        It 'skips with the reason of EntraOps, an exclusion or a missing rule' {
            Save-TestFindings @(
                @{ RuleId = 'EO.3001'; Status = 'Skipped'; Reason = 'No Configuration Analyzer data found.'; Results = @() }
                @{ RuleId = 'EO.3002'; Status = 'Excluded'; Results = @() }
                @{ RuleId = 'EO.3003'; Status = 'Skipped'; Results = @() }
            )
            Test-EntraOpsPackFinding -RuleId 'EO.3001' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'No Configuration Analyzer data found'
            Test-EntraOpsPackFinding -RuleId 'EO.3002' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'excluded'
            Test-EntraOpsPackFinding -RuleId 'EO.3003' | Should -BeNullOrEmpty
            $script:Detail.SkippedBecause | Should -Be 'NotApplicable'
            Test-EntraOpsPackFinding -RuleId 'EO.4004' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'no result for rule EO.4004'
        }

        It 'maps the reason code of EntraOps and shows the note of a passed or failed rule' {
            Save-TestFindings @(
                @{ RuleId = 'EO.3001'; Status = 'Skipped'; ReasonCode = 'NotApplicable'; Reason = 'No users in the scope of this rule (0 evaluated).'; Results = @() }
                @{ RuleId = 'EO.3002'; Status = 'Skipped'; ReasonCode = 'Unclassified'; Reason = 'Only unclassified objects are affected: 2 unclassified object(s).'; Results = @() }
                @{ RuleId = 'EO.3003'; Status = 'Skipped'; ReasonCode = 'MissingData'; Reason = 'No Configuration Analyzer data found.'; Results = @() }
                # Results of an older EntraOps version without ReasonCode: nothing in scope is still not applicable.
                @{ RuleId = 'EO.3004'; Status = 'Skipped'; Reason = 'No directory roles in the scope of this rule (0 evaluated).'; Results = @() }
                @{ RuleId = 'EO.4003'; Status = 'Passed'; ReasonCode = 'Note'; Reason = '1 excluded group(s) could not be resolved.'; EvaluatedCount = 2; FailedCount = 0; Results = @() }
                @{ RuleId = 'EO.4004'; Status = 'Failed'; ReasonCode = 'Note'; Reason = 'Set Findings.EmergencyAccessAccounts.'; EvaluatedCount = 2; FailedCount = 1; Results = @(@{ Instance = @{ DisplayName = 'Group'; ObjectType = 'group' }; Message = 'Excluded.' }) }
            )
            Test-EntraOpsPackFinding -RuleId 'EO.3001' | Should -BeNullOrEmpty
            $script:Detail.SkippedBecause | Should -Be 'NotApplicable'
            Test-EntraOpsPackFinding -RuleId 'EO.3002' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match '^EntraOps did not report rule EO.3002: Only unclassified objects'
            Test-EntraOpsPackFinding -RuleId 'EO.3003' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match '^EntraOps could not evaluate rule EO.3003: No Configuration Analyzer data found'
            Test-EntraOpsPackFinding -RuleId 'EO.3004' | Should -BeNullOrEmpty
            $script:Detail.SkippedBecause | Should -Be 'NotApplicable'
            Test-EntraOpsPackFinding -RuleId 'EO.4003' | Should -BeTrue
            $script:Detail.Result | Should -Match 'Note: 1 excluded group\(s\) could not be resolved\.'
            Test-EntraOpsPackFinding -RuleId 'EO.4004' | Should -BeFalse
            $script:Detail.Result | Should -Match 'Note: Set Findings\.EmergencyAccessAccounts\.'
        }

        It 'names the tenant of the results, which is compared only while Microsoft Graph is connected' {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; EvaluatedCount = 1; FailedCount = 0; Results = @() })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeTrue
            $script:Detail.Result | Should -Match '_EntraOps 1\.2\.0 results of tenant-1, \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC_'
        }

        It 'skips results of another tenant or results that are too old' {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; Results = @() })
            $script:GraphContext = [pscustomobject]@{ TenantId = 'tenant-2' }
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'for tenant tenant-1, but Maester is connected to tenant tenant-2'

            $script:GraphContext = $null
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; Results = @() }) -GeneratedAt (Get-Date).ToUniversalTime().AddDays(-10)
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'more than 7 days ago'
            $script:Settings['EntraOps.MaxFindingsAgeDays'] = 0
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeTrue
        }

        It 'skips with the setting to correct when EntraOps.MaxFindingsAgeDays is not a number of days (<Value>)' -ForEach @(
            @{ Value = 'seven' }
            @{ Value = '-1' }
        ) {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; Results = @() })
            $script:Settings['EntraOps.MaxFindingsAgeDays'] = $Value
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedBecause | Should -Be 'Custom'
            $script:Detail.SkippedCustomReason | Should -Match "EntraOps\.MaxFindingsAgeDays in maester-config\.json is '$([regex]::Escape($Value))', not a number of days"
        }

        It 'escapes the names and references of accepted risks for Markdown' {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Failed'; EvaluatedCount = 3; FailedCount = 1; AcceptedCount = 1
                    Results = @(@{ Instance = @{ DisplayName = 'Admin'; ObjectType = 'user' }; Message = 'Breach.' })
                    AcceptedResults = @(@{ Instance = @{ DisplayName = 'App | <b>B</b>'; ObjectType = 'servicePrincipal' }; Status = 'RiskAccepted'; Exception = @{ State = 'RiskAccepted'; Reference = "CHG-1`n<i>x</i>" } })
                })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape('listed apart: App \| &lt;b&gt;B&lt;/b&gt; (CHG-1 &lt;i&gt;x&lt;/i&gt;).'))
            # The table of accepted findings escapes them as well.
            $script:Detail.Result | Should -Match ([regex]::Escape('| 🤖 **App \| &lt;b&gt;B&lt;/b&gt;** | ⚖️ Risk accepted · CHG-1 &lt;i&gt;x&lt;/i&gt; |'))
        }

        It 'keeps names from the tenant from adding links to the result' {
            # A display name anyone can set on a group, app or guest must not become a link in a report read by administrators.
            $LinkName = 'Helpdesk\](https://evil.example/login) [x'
            $QuoteName = "a' [Reset your password](https://evil.example) 'b"
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Failed'; EvaluatedCount = 3; FailedCount = 2
                    Results = @(
                        @{ Instance = @{ ObjectId = 'aaaaaaaa-1111-1111-1111-111111111111'; DisplayName = $LinkName; ObjectType = 'group' }; Message = 'Breach.' }
                        @{ Instance = @{ DisplayName = 'Admin'; ObjectType = 'user' }; Message = "Object '$QuoteName' (group) reaches a higher tier." }
                    )
                    AcceptedResults = @(@{ Instance = @{ DisplayName = 'App'; ObjectType = 'servicePrincipal' }; Status = 'RiskAccepted'; Exception = @{ State = 'RiskAccepted'; Reference = '[CHG](https://evil.example)' } })
                })
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeFalse
            # No link target other than the admin center and the EntraOps reports: every "](" of a link follows an unescaped bracket.
            $script:Detail.Result | Should -Not -Match '(?<!\\)\]\(https://evil'
            $script:Detail.Result | Should -Match ([regex]::Escape('Helpdesk\\\](https://evil.example/login) \[x'))
            $script:Detail.Result | Should -Match ([regex]::Escape('\[Reset your password\](https://evil.example)'))
            $script:Detail.Result | Should -Match ([regex]::Escape('\[CHG\](https://evil.example)'))
        }

        It 'skips when no results are found, with how to create them' {
            $script:Settings = @{}
            $script:EntraOpsPackHasModule = $true
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'No EntraOps finding results \(findings\.json\) were found in'
            $script:Detail.SkippedCustomReason | Should -Match ([regex]::Escape((Join-Path $script:Empty 'EntraOps/Reports/Findings/data')))
            $script:Detail.SkippedCustomReason | Should -Match 'Invoke-EntraOpsAssessment .* or New-EntraOpsReportingData'
            $script:Detail.SkippedCustomReason | Should -Not -Match 'Save-EntraOpsFindingJson'
            $script:Detail.SkippedCustomReason | Should -Not -Match 'Install-PSResource'
            # Without the module on the machine, the reason tells how to install it.
            $script:EntraOpsPackHasModule = $false
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'Install-PSResource -Name EntraOps'
            $script:EntraOpsPackHasModule = $null
            $script:Settings = @{ 'EntraOps.FindingsPath' = (Join-Path $TestDrive 'missing') }
            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'No EntraOps finding results were found at .*missing'
        }

        It 'skips with what to check when the results cannot be used: <Case>' -ForEach @(
            @{ Case = 'a folder without findings.json'; Content = $null; Expected = 'the folder has no findings\.json\. Set EntraOps\.FindingsPath' }
            @{ Case = 'an empty file'; Content = ''; Expected = 'findings\.json \(EntraOps\.FindingsPath\) is empty\. EntraOps\.FindingsPath must point to' }
            @{ Case = 'a file that is cut off'; Content = '{ "SchemaVersion": "1.0", "Rules": [ { "RuleId": "EO.1'; Expected = 'could not be read: .+ The file may be incomplete' }
            @{ Case = 'another JSON file'; Content = '{ "Name": "x" }'; Expected = 'is no EntraOps finding results file \(it has no SchemaVersion and Rules\)' }
        ) {
            $Folder = Join-Path $TestDrive "unusable-$([guid]::NewGuid())"
            New-Item -ItemType Directory -Path $Folder | Out-Null
            if ($null -ne $Content) { Set-Content -LiteralPath (Join-Path $Folder 'findings.json') -Value $Content -NoNewline }
            $script:Settings = @{ 'EntraOps.FindingsPath' = $Folder }
            $script:EntraOpsPackWarnings = $null
            Test-EntraOpsPackFinding -RuleId 'EO.1001' 3>&1 | Should -BeOfType ([System.Management.Automation.WarningRecord])
            $script:Detail.SkippedBecause | Should -Be 'Custom'
            $script:Detail.SkippedCustomReason | Should -Match $Expected
            $script:Detail.SkippedCustomReason | Should -Match 'Invoke-EntraOpsAssessment'
            # The console tells it once per run, not with each test.
            @(Test-EntraOpsPackFinding -RuleId 'EO.1002' 3>&1) | Should -BeNullOrEmpty
        }

        It 'resolves a relative EntraOps.FindingsPath from the current folder and names both' {
            $script:Settings = @{ 'EntraOps.FindingsPath' = './Reports/Nowhere' }
            Test-EntraOpsPackFinding -RuleId 'EO.1001' 3> $null | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match ([regex]::Escape("No EntraOps finding results were found at $(Join-Path $script:Empty 'Reports/Nowhere') (EntraOps.FindingsPath './Reports/Nowhere', from the current folder"))
            $script:Detail.SkippedCustomReason | Should -Match 'the path does not exist\. Correct EntraOps\.FindingsPath'
        }

        It 'tells when EntraOps.ReportsPath has no EntraOps reports instead of linking to them' {
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Area = 'TierBreach'; Status = 'Failed'; EvaluatedCount = 1; FailedCount = 1; Results = @(@{ Instance = @{ ObjectId = 'aaaaaaaa-1111-1111-1111-111111111111'; DisplayName = 'Admin'; ObjectType = 'user' }; Message = 'Breach.' }) })
            $script:Settings['EntraOps.ReportsPath'] = Join-Path $TestDrive 'no-reports'
            $script:EntraOpsPackWarnings = $null
            Test-EntraOpsPackFinding -RuleId 'EO.1001' 3> $null | Should -BeFalse
            $script:Detail.Result | Should -Match 'EntraOps\.ReportsPath in maester-config\.json is .*no-reports, which has no EntraOps reports'
            $script:Detail.Result | Should -Not -Match 'no-reports/'
            $script:Detail.Result | Should -Not -Match 'Findings view'
        }

        It 'reads the results of the EntraOps working folder without the setting (<Location>)' -ForEach @(
            @{ Location = 'ENTRAOPS_ROOT' }
            @{ Location = 'home' }
            @{ Location = 'current folder' }
        ) {
            $Root = Join-Path $TestDrive "root-$([guid]::NewGuid())"
            $Folder = switch ($Location) {
                'ENTRAOPS_ROOT' { $env:ENTRAOPS_ROOT = $Root; Join-Path $Root 'Reports/Findings/data' }
                'home' { Join-Path $script:Empty 'EntraOps/Reports/Findings/data' }
                'current folder' { Join-Path $script:Empty 'Reports/Findings/data' }
            }
            Save-TestFindings @(@{ RuleId = 'EO.1001'; Status = 'Passed'; EvaluatedCount = 1; FailedCount = 0; Results = @() }) -Folder $Folder

            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeTrue
        }

        It 'reports a rule that EntraOps could not evaluate as an error with the reason' {
            Save-TestFindings @(@{ RuleId = 'EO.3001'; Status = 'Error'; Reason = 'The evaluation failed: boom.'; Results = @() })
            { Test-EntraOpsPackFinding -RuleId 'EO.3001' } | Should -Throw '*could not evaluate rule EO.3001*The evaluation failed: boom.*'
            # The result detail Maester shows instead of the error record.
            $script:Detail.Result | Should -Match 'could not evaluate rule EO.3001: The evaluation failed: boom'
        }

        It 'skips a deprecated rule with the reason of EntraOps' {
            Save-TestFindings @(@{ RuleId = 'EO.3002'; Status = 'Excluded'; Reason = 'Rule EO.3002 is deprecated.'; Results = @() })
            Test-EntraOpsPackFinding -RuleId 'EO.3002' | Should -BeNullOrEmpty
            $script:Detail.SkippedCustomReason | Should -Match 'did not evaluate rule EO.3002: Rule EO.3002 is deprecated'
        }

        It 'names the data gaps that affect a rule, apart from those EO.4010 and EO.4011 report themselves' {
            $Folder = Join-Path $TestDrive ([guid]::NewGuid())
            New-Item -ItemType Directory -Path $Folder -Force | Out-Null
            $Gap = 'The Object Classification File is enabled, but ./Classification/ObjectClassification.json does not exist.'
            $OriginGap = 'The origin of 2 group(s) with role assignments (Group A, Group B) is unknown.'
            [ordered]@{
                SchemaVersion = '1.0'; GeneratedAt = (Get-Date).ToUniversalTime().ToString('o'); Generator = @{ Name = 'EntraOps'; Version = '1.2.0' }; TenantId = 'tenant-1'
                DataGaps = @(
                    @{ Code = 'ObjectClassificationFileMissing'; Message = $Gap; Count = 1; RuleIds = @('EO.1001', 'EO.1003', 'EO.2001') }
                    @{ Code = 'GroupOriginUnknown'; Message = $OriginGap; Count = 2; RuleIds = @('EO.4010', 'EO.4011') }
                )
                Rules = @(
                    @{ RuleId = 'EO.1001'; Area = 'TierBreach'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; Results = @() }
                    @{ RuleId = 'EO.1003'; Area = 'TierBreach'; Status = 'Skipped'; ReasonCode = 'Unclassified'; Reason = 'Only unclassified objects are affected: 1 unclassified object(s).'; Results = @() }
                    @{ RuleId = 'EO.3004'; Area = 'PimRequestFlow'; Status = 'Passed'; EvaluatedCount = 3; FailedCount = 0; Results = @() }
                    @{ RuleId = 'EO.4011'; Area = 'PrivilegedEAM'; Status = 'Passed'; ReasonCode = 'Note'; Reason = 'The origin of 1 group(s) with Control Plane access (Group A) is unknown.'; EvaluatedCount = 3; FailedCount = 0; Results = @() }
                    @{ RuleId = 'EO.2001'; Area = 'PrivilegedAssets'; Status = 'Excluded'; Results = @() }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Folder 'findings.json')
            $script:Settings = @{ 'EntraOps.FindingsPath' = $Folder }

            Test-EntraOpsPackFinding -RuleId 'EO.1001' | Should -BeTrue
            $script:Detail.Result | Should -Match ([regex]::Escape("⚠️ Data gap: $Gap"))
            Test-EntraOpsPackFinding -RuleId 'EO.1003' | Should -BeNullOrEmpty
            $script:Detail.Result | Should -Match ([regex]::Escape("⚠️ Data gap: $Gap"))
            Test-EntraOpsPackFinding -RuleId 'EO.3004' | Should -BeTrue
            $script:Detail.Result | Should -Not -Match 'Data gap'
            Test-EntraOpsPackFinding -RuleId 'EO.4011' | Should -BeTrue
            $script:Detail.Result | Should -Match 'with Control Plane access \(Group A\)'
            $script:Detail.Result | Should -Not -Match 'Data gap|Group B'
            Test-EntraOpsPackFinding -RuleId 'EO.2001' | Should -BeNullOrEmpty
            $script:Detail.Result | Should -Not -Match 'Data gap'
        }

        It 'links an application to its app registration by its appId and adds its tier as a fact' {
            $AppId = 'aaaaaaaa-8888-8888-8888-888888888888'
            $ObjectId = 'bbbbbbbb-8888-8888-8888-888888888888'
            Save-TestFindings @(@{ RuleId = 'EO.7001'; Area = 'PrivilegedEAM'; Status = 'Failed'; EvaluatedCount = 2; FailedCount = 2; Results = @(
                        @{ Instance = @{ ObjectId = $ObjectId; DisplayName = 'Deploy App'; ObjectType = 'application'; AdminTierLevelName = 'ManagementPlane' }; Evidence = @{ AppId = $AppId }; Message = 'Has owners.' }
                        @{ Instance = @{ ObjectId = 'cccccccc-9999-9999-9999-999999999999'; DisplayName = 'Old App'; ObjectType = 'application'; AdminTierLevelName = 'ManagementPlane' }; Message = 'Has owners.' }
                    ) })
            function Test-EntraOpsPackMaesterCommand { param($Name) $Name -eq 'Add-MtAffectedObjectFact' }
            $script:Facts = [System.Collections.Generic.List[object]]::new()
            function Add-MtAffectedObjectFact { param([Parameter(ValueFromPipeline)] $InputObject, $Source, $AsOf) process { $script:Facts.Add($InputObject) } }

            Test-EntraOpsPackFinding -RuleId 'EO.7001' | Should -BeFalse
            $script:Detail.Result | Should -Match ([regex]::Escape("**[Deploy App](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$AppId)**"))
            $script:Detail.Result | Should -Match ([regex]::Escape('🧩 **Old App**'))
            $script:Detail.GraphObjects | Should -BeNullOrEmpty
            $script:Facts.Count | Should -Be 1
            $script:Facts[0].Type | Should -Be 'AppRegistration'
            $script:Facts[0].Id | Should -Be $AppId
            $script:Facts[0].Fact[0].Value | Should -Be 'Management Plane'
        }

        It 'uses the admin center of the cloud of the Microsoft Graph connection' {
            Get-EntraOpsPackPortalUrl | Should -Be 'https://entra.microsoft.com/'
            $script:GraphContext = [pscustomobject]@{ TenantId = 'tenant-1'; Environment = 'USGov' }
            Get-EntraOpsPackPortalUrl | Should -BeNullOrEmpty
            function Test-EntraOpsPackMaesterCommand { param($Name) $Name -eq 'Get-MtAdminPortalUrl' }
            function Get-MtAdminPortalUrl { param($Environment, $Portal) if ($Environment -eq 'USGov' -and $Portal -eq 'Entra') { 'https://entra.microsoft.us/' } }
            Get-EntraOpsPackPortalUrl | Should -Be 'https://entra.microsoft.us/'
            $script:GraphContext = [pscustomobject]@{ TenantId = 'tenant-1'; Environment = 'Contoso' }
            Get-EntraOpsPackPortalUrl | Should -BeNullOrEmpty
        }

        It 'names the Maester tests of the rules that a reason refers to, but keeps the rule of the reason' {
            $Rules = @([pscustomobject]@{ RuleId = 'EO.2001'; MaesterTestId = 'MP.EOPS.2001' }, [pscustomobject]@{ RuleId = 'EO.1003'; MaesterTestId = 'MP.EOPS.1003' })
            ConvertTo-EntraOpsPackTestReference -Text 'Classify these objects (EO.2001) to evaluate EO.1003, see EO.9999.' -Rules $Rules -RuleId 'EO.1003' | Should -Be 'Classify these objects (MP.EOPS.2001) to evaluate EO.1003, see EO.9999.'
            ConvertTo-EntraOpsPackTestReference -Text '' -Rules $Rules -RuleId 'EO.1003' | Should -BeNullOrEmpty
        }
    }
}
