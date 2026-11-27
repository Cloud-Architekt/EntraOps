#Requires -Modules Pester

Describe 'Resolve-EntraOpsContentRef' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsContentRef.ps1"
        function Invoke-EntraOpsGitHubRequest { param($Uri, $Token, $Headers, $OutFile) }
        function Get-EntraOpsModuleVersion {}

        # EntraOps.psd1 at a ref of the branch; the history lists the commits that changed it, newest first.
        $script:ManifestVersions = @{}
        $script:History = @()
        $script:Requests = [System.Collections.Generic.List[string]]::new()
        $script:MockGitHub = {
            param($Uri)
            $script:Requests.Add($Uri)
            # The history in pages, as the GitHub API lists it with per_page and page.
            if ($Uri -like '*/commits?*') {
                $PageSize = if ($Uri -match '[?&]per_page=(\d+)') { [int]$Matches[1] } else { 30 }
                $Page = if ($Uri -match '[?&]page=(\d+)') { [int]$Matches[1] } else { 1 }
                return @($script:History | Select-Object -Skip (($Page - 1) * $PageSize) -First $PageSize)
            }
            $Ref = if ($Uri -match 'raw\.githubusercontent\.com/[^/]+/[^/]+/(?<Ref>.+)/EntraOps/EntraOps\.psd1$') { $Matches.Ref } elseif ($Uri -match '\?ref=(?<Ref>.+)$') { $Matches.Ref }
            if ($script:ManifestVersions.ContainsKey($Ref)) { "@{ ModuleVersion = '$($script:ManifestVersions[$Ref])' }" } else { throw "404 $Ref" }
        }
    }

    BeforeEach {
        $script:Requests.Clear()
        Mock Invoke-EntraOpsGitHubRequest $script:MockGitHub
    }

    It 'uses the branch when its head has the module version, without a GitHub API request' {
        $script:ManifestVersions = @{ main = '1.2.0' }

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeTrue
        $Result.Resolution | Should -Be 'BranchHead'
        $Result.Ref | Should -Be 'main'
        @($script:Requests | Where-Object { $_ -like 'https://api.github.com/*' }).Count | Should -Be 0
    }

    It 'reports no match without searching the history when the module is newer than the branch' {
        $script:ManifestVersions = @{ main = '1.1.0' }

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeFalse
        $Result.Resolution | Should -Be 'NoMatch'
        $Result.Ref | Should -Be 'main'
        $Result.BranchVersion | Should -Be ([version]'1.1.0')
        @($script:Requests | Where-Object { $_ -like '*/commits?*' }).Count | Should -Be 0
    }

    It 'finds the newest content of an older module version: the parent of the commit that changed the version' {
        $script:ManifestVersions = @{ main = '1.3.0'; c3 = '1.3.0'; c2 = '1.3.0'; 'p2-last-1.2.0' = '1.2.0'; c1 = '1.2.0'; c0 = '1.1.0' }
        $script:History = @(
            [pscustomobject]@{ sha = 'c3'; parents = @([pscustomobject]@{ sha = 'p3' }) }
            [pscustomobject]@{ sha = 'c2'; parents = @([pscustomobject]@{ sha = 'p2-last-1.2.0' }) }
            [pscustomobject]@{ sha = 'c1'; parents = @([pscustomobject]@{ sha = 'p1' }) }
            [pscustomobject]@{ sha = 'c0'; parents = @([pscustomobject]@{ sha = 'p0' }) }
        )

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeTrue
        $Result.Resolution | Should -Be 'BranchHistory'
        $Result.Ref | Should -Be 'p2-last-1.2.0'
        $Result.ContentVersion | Should -Be ([version]'1.2.0')
    }

    It 'uses the release tag of the module version without searching the history (<Tag>)' -ForEach @(
        @{ Tag = 'v1.2.0' }
        @{ Tag = '1.2.0' }
    ) {
        $script:ManifestVersions = @{ main = '1.3.0'; $Tag = '1.2.0' }

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeTrue
        $Result.Resolution | Should -Be 'ReleaseTag'
        $Result.Ref | Should -Be $Tag
        @($script:Requests | Where-Object { $_ -like '*/commits?*' }).Count | Should -Be 0
    }

    It 'ignores a tag whose manifest has another version' {
        $script:ManifestVersions = @{ main = '1.3.0'; 'v1.2.0' = '1.3.0'; c1 = '1.3.0'; p1 = '1.2.0'; c0 = '1.2.0' }
        $script:History = @(
            [pscustomobject]@{ sha = 'c1'; parents = @([pscustomobject]@{ sha = 'p1' }) }
            [pscustomobject]@{ sha = 'c0'; parents = @([pscustomobject]@{ sha = 'p0' }) }
        )

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Resolution | Should -Be 'BranchHistory'
        $Result.Ref | Should -Be 'p1'
    }

    It 'finds the module version beyond the first page of the history' {
        # 120 commits of 1.3.0 before the one that changed the version from 1.2.0.
        $script:ManifestVersions = @{ main = '1.3.0'; 'p-last-1.2.0' = '1.2.0'; old = '1.2.0' }
        $script:History = @(
            foreach ($Index in 120..1) {
                $script:ManifestVersions["n$Index"] = '1.3.0'
                [pscustomobject]@{ sha = "n$Index"; parents = @([pscustomobject]@{ sha = $(if ($Index -eq 1) { 'p-last-1.2.0' } else { "n$($Index - 1)" }) }) }
            }
            [pscustomobject]@{ sha = 'old'; parents = @([pscustomobject]@{ sha = 'older' }) }
        )

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeTrue
        $Result.Resolution | Should -Be 'BranchHistory'
        $Result.Ref | Should -Be 'p-last-1.2.0'
        @($script:Requests | Where-Object { $_ -like '*/commits?*per_page=100&page=2' }).Count | Should -Be 1
    }

    It 'verifies the version at the candidate and uses the matching commit when the parent is of another line' {
        # c2 of a merged side branch is listed before c1 by date; its parent has another version.
        $script:ManifestVersions = @{ main = '1.3.0'; c2 = '1.3.0'; 'side-parent' = '1.3.0'; c1 = '1.2.0' }
        $script:History = @(
            [pscustomobject]@{ sha = 'c2'; parents = @([pscustomobject]@{ sha = 'side-parent' }) }
            [pscustomobject]@{ sha = 'c1'; parents = @([pscustomobject]@{ sha = 'p1' }) }
        )

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeTrue
        $Result.Ref | Should -Be 'c1'
        $Result.ContentVersion | Should -Be ([version]'1.2.0')
    }

    It 'stops after the page limit and reports no match' {
        $script:ManifestVersions = @{ main = '1.3.0' }
        $script:History = @(
            foreach ($Index in 400..1) {
                $script:ManifestVersions["n$Index"] = '1.3.0'
                [pscustomobject]@{ sha = "n$Index"; parents = @([pscustomobject]@{ sha = "n$($Index - 1)" }) }
            }
        )

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeFalse
        $Result.Resolution | Should -Be 'NoMatch'
        $Result.Ref | Should -Be 'main'
        @($script:Requests | Where-Object { $_ -like '*/commits?*' }).Count | Should -Be 3
    }

    It 'fails instead of reporting no match when GitHub cannot be read' {
        $script:ManifestVersions = @{ main = '1.3.0' }
        Mock Invoke-EntraOpsGitHubRequest { throw 'GitHub rate limit exceeded' } -ParameterFilter { $Uri -like '*/v1.2.0/*' }

        { Resolve-EntraOpsContentRef -ModuleVersion '1.2.0' } | Should -Throw '*rate limit*'
    }

    It 'reports no match when the module version is not in the history of the branch' {
        $script:ManifestVersions = @{ main = '1.3.0'; c1 = '1.3.0'; c0 = '1.1.0' }
        $script:History = @(
            [pscustomobject]@{ sha = 'c1'; parents = @([pscustomobject]@{ sha = 'p1' }) }
            [pscustomobject]@{ sha = 'c0'; parents = @([pscustomobject]@{ sha = 'p0' }) }
        )

        $Result = Resolve-EntraOpsContentRef -ModuleVersion '1.2.0'

        $Result.Matched | Should -BeFalse
        $Result.Ref | Should -Be 'main'
    }

    It 'reads the private Insiders repository through the API with the token' {
        $script:ManifestVersions = @{ 'feature/FindingReport' = '1.2.0' }

        $Result = Resolve-EntraOpsContentRef -Repository 'EntraOps-Insiders' -Branch 'feature/FindingReport' -ModuleVersion '1.2.0' -PersonalAccessToken 'pat'

        $Result.Matched | Should -BeTrue
        Should -Invoke Invoke-EntraOpsGitHubRequest -Times 1 -Exactly -ParameterFilter { $Uri -like 'https://api.github.com/repos/Cloud-Architekt/EntraOps-Insiders/contents/EntraOps/EntraOps.psd1?ref=feature/FindingReport' -and $Token -eq 'pat' }
    }
}

Describe 'Get-EntraOpsModuleVersion' {
    It 'reads the manifest version also when the module is imported from EntraOps.psm1' {
        $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $ManifestVersion = [version](Import-PowerShellDataFile (Join-Path $RepositoryRoot 'EntraOps/EntraOps.psd1')).ModuleVersion
        try {
            Import-Module (Join-Path $RepositoryRoot 'EntraOps/EntraOps.psm1') -Force -WarningAction SilentlyContinue
            # The module object has no version without its manifest.
            (Get-Module EntraOps).Version | Should -Be ([version]'0.0')
            InModuleScope EntraOps { Get-EntraOpsModuleVersion } | Should -Be $ManifestVersion
        } finally {
            Remove-Module EntraOps -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-EntraOpsContentSource from the repository checkout of the module' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
    BeforeAll {
        $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $RepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    It 'uses only the files tracked in git, never generated report data of the checkout' {
        $Checkout = Join-Path $TestDrive 'checkout'
        New-Item -ItemType Directory -Path "$Checkout/EntraOps", "$Checkout/Reports/EamDashboard/data", "$Checkout/Classification" -Force | Out-Null
        Set-Content -LiteralPath "$Checkout/EntraOpsUpdateContract.json" -Value '{}'
        Set-Content -LiteralPath "$Checkout/Reports/index.html" -Value 'portal'
        Set-Content -LiteralPath "$Checkout/Classification/Global.json" -Value 'tenant exclusions'
        & git -C $Checkout init --quiet
        & git -C $Checkout add --all
        # Generated after the commit, like the report data of a tenant in a working copy.
        Set-Content -LiteralPath "$Checkout/Reports/EamDashboard/data/eam-dashboard-data.js" -Value 'tenant data'

        $Source = InModuleScope EntraOps -Parameters @{ ModuleBase = "$Checkout/EntraOps" } { param($ModuleBase) Get-EntraOpsContentSource -Folder Reports -ModuleBase $ModuleBase }
        try {
            $Source.Resolution | Should -Be 'LocalCheckout'
            $Source.Matched | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $Source.SourceRoot 'Reports/index.html') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $Source.SourceRoot 'Reports/EamDashboard/data/eam-dashboard-data.js') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $Source.SourceRoot 'Classification') | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $Source.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'downloads the classification templates instead of using the checkout, whose classification can belong to its tenant' {
        Mock -ModuleName EntraOps Resolve-EntraOpsContentRef { [pscustomobject]@{ Ref = 'main'; Resolution = 'BranchHead' } }
        Mock -ModuleName EntraOps Get-EntraOpsSourceArchive { [pscustomobject]@{ SourceRoot = $TestDrive; TemporaryFolder = $null; Repository = 'Cloud-Architekt/EntraOps'; Ref = $Ref; ContentVersion = $null } }

        $Source = InModuleScope EntraOps -Parameters @{ ModuleBase = "$TestDrive/checkout/EntraOps" } { param($ModuleBase) Get-EntraOpsContentSource -Folder Classification, Reports -ModuleBase $ModuleBase }

        $Source.Resolution | Should -Be 'BranchHead'
        Should -Invoke -ModuleName EntraOps Get-EntraOpsSourceArchive -Times 1 -Exactly
    }
}

Describe 'Get-EntraOpsContentSource without content of the module version' {
    BeforeAll {
        $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $RepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    BeforeEach {
        Mock -ModuleName EntraOps Test-EntraOpsRepositoryCheckout { $false }
        Mock -ModuleName EntraOps Resolve-EntraOpsContentRef { [pscustomobject]@{ Ref = 'main'; ContentVersion = [version]'1.1.0'; Matched = $false; Resolution = 'NoMatch' } }
        Mock -ModuleName EntraOps Get-EntraOpsSourceArchive { [pscustomobject]@{ SourceRoot = $TestDrive; TemporaryFolder = $null; Repository = 'Cloud-Architekt/EntraOps'; Ref = $Ref; ContentVersion = [version]'1.1.0' } }
    }

    It 'skips the download with -SkipDownloadWithoutMatch, for a caller that keeps the existing content' {
        $Source = InModuleScope EntraOps { Get-EntraOpsContentSource -Folder Reports -SkipDownloadWithoutMatch }

        $Source.Matched | Should -BeFalse
        $Source.Resolution | Should -Be 'NoMatch'
        $Source.SourceRoot | Should -BeNullOrEmpty
        $Source.ContentVersion | Should -Be ([version]'1.1.0')
        Should -Invoke -ModuleName EntraOps Get-EntraOpsSourceArchive -Times 0
    }

    It 'downloads the branch head without the switch' {
        $Source = InModuleScope EntraOps { Get-EntraOpsContentSource -Folder Reports }

        $Source.Matched | Should -BeFalse
        Should -Invoke -ModuleName EntraOps Get-EntraOpsSourceArchive -Times 1 -Exactly -ParameterFilter { $Ref -eq 'main' }
    }
}

Describe 'Resolve-EntraOpsContentRepository' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsContentSource.ps1"
        function New-TestConfig {
            param($Repository)
            $File = Join-Path $TestDrive "$([guid]::NewGuid().ToString('N')).json"
            $Update = if ($null -ne $Repository) { @{ Repository = $Repository } } else { @{ Branch = 'main' } }
            @{ TenantName = 'contoso.onmicrosoft.com'; AutomatedEntraOpsUpdate = $Update } | ConvertTo-Json | Set-Content -LiteralPath $File
            $File
        }
    }

    It 'takes the release channel of the deployment from AutomatedEntraOpsUpdate.Repository (<Value>)' -ForEach @(
        @{ Value = 'EntraOps-Insiders'; Expected = 'EntraOps-Insiders' }
        @{ Value = 'Cloud-Architekt/EntraOps-Insiders'; Expected = 'EntraOps-Insiders' }
        @{ Value = 'entraops'; Expected = 'EntraOps' }
    ) {
        $File = New-TestConfig -Repository $Value

        $Result = Resolve-EntraOpsContentRepository -ConfigFilePath (Join-Path $TestDrive 'missing.json'), $File

        $Result.Repository | Should -BeExactly $Expected
        $Result.Reason | Should -Be "AutomatedEntraOpsUpdate.Repository in $File"
    }

    It 'uses the public repository without configuration or without the setting' {
        (Resolve-EntraOpsContentRepository -ConfigFilePath (Join-Path $TestDrive 'missing.json')).Repository | Should -Be 'EntraOps'
        (Resolve-EntraOpsContentRepository).Reason | Should -Be 'default, no EntraOpsConfig.json'
        $Result = Resolve-EntraOpsContentRepository -ConfigFilePath (New-TestConfig)
        $Result.Repository | Should -Be 'EntraOps'
        $Result.Reason | Should -Match '^default, no AutomatedEntraOpsUpdate.Repository in '
    }

    It 'uses the configuration the caller has already read' {
        $Result = Resolve-EntraOpsContentRepository -Config ([pscustomobject]@{ AutomatedEntraOpsUpdate = [pscustomobject]@{ Repository = 'EntraOps-Insiders' } })

        $Result.Repository | Should -Be 'EntraOps-Insiders'
        $Result.Reason | Should -Be 'AutomatedEntraOpsUpdate.Repository in the configuration'
    }

    It 'warns and uses the public repository for <Case>' -ForEach @(
        @{ Case = 'an unknown repository'; Content = '{ "AutomatedEntraOpsUpdate": { "Repository": "Contoso/EntraOps-Fork" } }'; Warning = "*'Contoso/EntraOps-Fork'*is not a distribution repository*" }
        @{ Case = 'a configuration that is not valid JSON'; Content = '{ not json'; Warning = '*not valid JSON*public*' }
    ) {
        $File = Join-Path $TestDrive "$([guid]::NewGuid().ToString('N')).json"
        Set-Content -LiteralPath $File -Value $Content

        $Result = Resolve-EntraOpsContentRepository -ConfigFilePath $File -WarningVariable Warnings -WarningAction SilentlyContinue

        $Result.Repository | Should -Be 'EntraOps'
        ($Warnings -join ' ') | Should -BeLike $Warning
    }

    It 'knows the distribution repositories of the catalog in EntraOpsUpdateContract.json' {
        $Catalog = (Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOpsUpdateContract.json') -Raw | ConvertFrom-Json).DistributionRepositories
        foreach ($FullName in $Catalog.PSObject.Properties.Name) {
            $Name = $FullName -replace '^Cloud-Architekt/', ''
            (Resolve-EntraOpsContentRepository -Config ([pscustomobject]@{ AutomatedEntraOpsUpdate = [pscustomobject]@{ Repository = $FullName } })).Repository | Should -BeExactly $Name
        }
        # The parameters of the content commands accept the same repositories.
        $Names = @($Catalog.PSObject.Properties.Name | ForEach-Object { $_ -replace '^Cloud-Architekt/', '' } | Sort-Object)
        foreach ($File in 'EntraOps/Public/Configuration/Initialize-EntraOpsWorkspace.ps1', 'EntraOps/Public/Reportings/Install-EntraOpsReportingFolder.ps1', 'EntraOps/Public/Core/Invoke-EntraOpsAssessment.ps1') {
            $Ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:TestRepositoryRoot $File), [ref]$null, [ref]$null)
            $Parameter = $Ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.ParameterAst] -and $Node.Name.VariablePath.UserPath -in 'Repository', 'ContentRepository' }, $true) | Select-Object -First 1
            $ValidateSet = $Parameter.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
            @($ValidateSet.PositionalArguments.Value | Sort-Object) | Should -Be $Names -Because $File
        }
    }
}
