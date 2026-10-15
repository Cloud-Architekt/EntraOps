#Requires -Modules Pester

BeforeDiscovery {
    $script:HasAdoScripts = Test-Path -LiteralPath (Join-Path $PSScriptRoot '../../.azure-pipelines/scripts/Ado-GitAuth.ps1') -PathType Leaf
    $script:HasGit = [bool](Get-Command git -ErrorAction SilentlyContinue)
}

BeforeAll {
    $script:ScriptRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../.azure-pipelines/scripts')).Path
    $script:SavedEnvironment = @{}
    foreach ($Name in 'SYSTEM_COLLECTIONURI', 'BUILD_SOURCEBRANCH', 'SYSTEM_ACCESSTOKEN', 'SYSTEM_TEAMPROJECTID', 'BUILD_REPOSITORY_ID', 'BUILD_BUILDID', 'ENTRAOPS_PAT', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1') {
        $script:SavedEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name)
    }

    function Invoke-TestGit {
        param ([Parameter(Mandatory = $true)][string]$Path, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
        $Output = & git -C $Path -c user.email=test@contoso.com -c user.name=Test -c init.defaultBranch=main @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed: $Output" }
        return $Output
    }

    # Bare repositories are addressed with --git-dir, which works with safe.bareRepository=explicit
    function Invoke-TestBareGit {
        param ([Parameter(Mandatory = $true)][string]$Path, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
        $Output = & git --git-dir $Path @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed: $Output" }
        return $Output
    }

    # Remote with one commit on main and a clone that represents the pipeline checkout
    function New-TestRepository {
        param ([Parameter(Mandatory = $true)][string]$Root)
        $Remote = Join-Path $Root 'remote.git'
        $Clone = Join-Path $Root 'clone'
        New-Item -ItemType Directory -Path $Remote, $Clone -Force | Out-Null
        & git init --quiet --bare --initial-branch=main $Remote | Out-Null
        Invoke-TestGit -Path $Clone init --initial-branch=main | Out-Null
        Invoke-TestGit -Path $Clone remote add origin $Remote | Out-Null
        Set-Content -LiteralPath (Join-Path $Clone 'README.md') -Value 'v1'
        Invoke-TestGit -Path $Clone add --all | Out-Null
        Invoke-TestGit -Path $Clone commit -m 'v1' | Out-Null
        Invoke-TestGit -Path $Clone push origin HEAD:refs/heads/main | Out-Null
        return @{ Remote = $Remote; Clone = $Clone }
    }

    function Add-RemoteCommit {
        param ([Parameter(Mandatory = $true)][string]$Remote, [Parameter(Mandatory = $true)][string]$Root, [string]$File = 'PrivilegedEAM.json', [string]$Branch = 'main')
        $Writer = Join-Path $Root ([guid]::NewGuid().ToString())
        & git clone --quiet --branch $Branch $Remote $Writer 2>&1 | Out-Null
        Set-Content -LiteralPath (Join-Path $Writer $File) -Value ([guid]::NewGuid().ToString())
        Invoke-TestGit -Path $Writer add --all | Out-Null
        Invoke-TestGit -Path $Writer commit -m "Add $File" | Out-Null
        Invoke-TestGit -Path $Writer push origin "HEAD:refs/heads/$Branch" | Out-Null
        return ([string](Invoke-TestGit -Path $Writer rev-parse HEAD)).Trim()
    }
}

AfterAll {
    foreach ($Name in $script:SavedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($Name, $script:SavedEnvironment[$Name])
    }
}

Describe 'Azure DevOps git authentication helpers' -Skip:(-not $HasAdoScripts) {
    BeforeAll {
        . (Join-Path $script:ScriptRoot 'Ado-GitAuth.ps1')
    }

    AfterEach {
        foreach ($Name in 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1') {
            [Environment]::SetEnvironmentVariable($Name, $script:SavedEnvironment[$Name])
        }
    }

    It 'treats an undefined pipeline variable macro as an empty secret' {
        Get-EntraOpsAdoSecretValue -Value '$(EntraOpsUpdatePat)' | Should -BeExactly ''
        Get-EntraOpsAdoSecretValue -Value '' | Should -BeExactly ''
        Get-EntraOpsAdoSecretValue -Value 'pat-value' | Should -BeExactly 'pat-value'
    }

    It 'keeps the full branch name and rejects refs that are not branches' {
        Get-EntraOpsAdoBranchName -SourceBranch 'refs/heads/release/v1' | Should -Be 'release/v1'
        { Get-EntraOpsAdoBranchName -SourceBranch 'refs/pull/1/merge' } | Should -Throw '*Unable to determine the branch*'
        { Get-EntraOpsAdoBranchName -SourceBranch '' } | Should -Throw '*Unable to determine the branch*'
    }

    It 'only scopes credentials to an absolute HTTPS collection URI' {
        Get-EntraOpsAdoCollectionUri -CollectionUri 'https://dev.azure.com/contoso/' | Should -Be 'https://dev.azure.com/contoso'
        { Get-EntraOpsAdoCollectionUri -CollectionUri 'http://dev.azure.com/contoso/' } | Should -Throw '*absolute HTTPS URI*'
    }

    It 'passes the token only while the git commands run and restores the environment, also on failure' {
        $env:GIT_CONFIG_COUNT = '7'
        Remove-Item -LiteralPath Env:GIT_CONFIG_VALUE_1 -ErrorAction SilentlyContinue
        $script:Seen = $null

        Invoke-EntraOpsAdoAuthenticatedGit -AccessToken 'secret-token' -CollectionUri 'https://dev.azure.com/contoso' -ScriptBlock {
            $script:Seen = @{ Count = $env:GIT_CONFIG_COUNT; Key = $env:GIT_CONFIG_KEY_1; Value = $env:GIT_CONFIG_VALUE_1; Reset = $env:GIT_CONFIG_VALUE_0 }
        }
        $script:Seen.Count | Should -Be '2'
        $script:Seen.Key | Should -Be 'http.https://dev.azure.com/contoso/.extraHeader'
        $script:Seen.Value | Should -BeExactly 'AUTHORIZATION: bearer secret-token'
        $script:Seen.Reset | Should -BeExactly ''
        $env:GIT_CONFIG_COUNT | Should -Be '7'
        $env:GIT_CONFIG_VALUE_1 | Should -BeNullOrEmpty

        { Invoke-EntraOpsAdoAuthenticatedGit -AccessToken 'secret-token' -CollectionUri 'https://dev.azure.com/contoso' -ScriptBlock { throw 'git failed' } } | Should -Throw 'git failed'
        $env:GIT_CONFIG_COUNT | Should -Be '7'
        $env:GIT_CONFIG_VALUE_1 | Should -BeNullOrEmpty
    }

    It 'requires the job access token' {
        { Invoke-EntraOpsAdoAuthenticatedGit -AccessToken '' -CollectionUri 'https://dev.azure.com/contoso' -ScriptBlock {} } | Should -Throw '*System.AccessToken*'
    }
}

Describe 'Ado-CheckoutLatest' -Skip:(-not $HasAdoScripts -or -not $HasGit) {
    BeforeEach {
        $env:SYSTEM_COLLECTIONURI = 'https://dev.azure.com/contoso/'
    }

    It 'checks out the commit pushed after the run was queued without storing the token' {
        $Repository = New-TestRepository -Root (Join-Path $TestDrive 'latest')
        $LatestCommit = Add-RemoteCommit -Remote $Repository.Remote -Root $TestDrive

        Push-Location -LiteralPath $Repository.Clone
        try {
            & (Join-Path $script:ScriptRoot 'Ado-CheckoutLatest.ps1') -SourceBranch 'refs/heads/main' -AccessToken 'secret-token' 6>$null
        } finally {
            Pop-Location
        }

        ([string](Invoke-TestGit -Path $Repository.Clone rev-parse HEAD)).Trim() | Should -Be $LatestCommit
        Test-Path -LiteralPath (Join-Path $Repository.Clone 'PrivilegedEAM.json') | Should -BeTrue
        Get-Content -LiteralPath (Join-Path $Repository.Clone '.git/config') -Raw | Should -Not -Match 'secret-token|extraHeader'
    }
}

Describe 'Azure DevOps update entry scripts' -Skip:(-not $HasAdoScripts) {
    BeforeAll {
        function Get-EntraOpsUpdateCandidate { param($ConfigFile, $DestinationPath, $ExpectedSourceCommit) }
        function Install-EntraOpsUpdateCandidate { param($ConfigFile, $SourceCommit, [bool]$ValidationRequired, [bool]$BrowserTestsValidated) }
    }

    BeforeEach {
        $EntryRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $EntryRoot -Force | Out-Null
        Copy-Item -Path (Join-Path $script:ScriptRoot '*.ps1') -Destination $EntryRoot
        $State = @{ PublisherPath = Join-Path $TestDrive 'trusted-publisher'; TokenAtDownload = $null }
        Mock Import-Module {} -ParameterFilter { $Name -like '*EntraOps.psd1' }
        Mock Get-EntraOpsUpdateCandidate {
            # Preparation must freeze both files before it even downloads the candidate.
            Test-Path -LiteralPath (Join-Path $State.PublisherPath 'Publish-EntraOpsAdoUpdate.ps1') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $State.PublisherPath 'Ado-GitAuth.ps1') | Should -BeTrue
            $State.TokenAtDownload = $env:ENTRAOPS_PAT
        }
        Mock Install-EntraOpsUpdateCandidate {}
    }

    AfterEach {
        [Environment]::SetEnvironmentVariable('ENTRAOPS_PAT', $script:SavedEnvironment['ENTRAOPS_PAT'])
    }

    It 'freezes the trusted publisher and removes an unresolved PAT before downloading the exact commit' {
        $env:ENTRAOPS_PAT = '$(EntraOpsUpdatePat)'
        $Publisher = Get-Content -LiteralPath (Join-Path $EntryRoot 'Publish-EntraOpsAdoUpdate.ps1') -Raw
        $Auth = Get-Content -LiteralPath (Join-Path $EntryRoot 'Ado-GitAuth.ps1') -Raw

        & (Join-Path $EntryRoot 'Prepare-EntraOpsAdoUpdate.ps1') -ConfigFile './custom.json' -SourceCommit ('a' * 40) -PublisherPath $State.PublisherPath

        $State.TokenAtDownload | Should -BeNullOrEmpty
        Should -Invoke Get-EntraOpsUpdateCandidate -Times 1 -Exactly -ParameterFilter {
            $ConfigFile -eq './custom.json' -and $DestinationPath -eq './TmpUpdate' -and $ExpectedSourceCommit -eq ('a' * 40)
        }
        # Simulate the update replacing the source scripts; publication must still use the frozen copies.
        Set-Content -LiteralPath (Join-Path $EntryRoot 'Publish-EntraOpsAdoUpdate.ps1') -Value '# candidate publisher'
        Set-Content -LiteralPath (Join-Path $EntryRoot 'Ado-GitAuth.ps1') -Value '# candidate authentication helper'
        Get-Content -LiteralPath (Join-Path $State.PublisherPath 'Publish-EntraOpsAdoUpdate.ps1') -Raw | Should -BeExactly $Publisher
        Get-Content -LiteralPath (Join-Path $State.PublisherPath 'Ado-GitAuth.ps1') -Raw | Should -BeExactly $Auth
    }

    It 'keeps a configured upstream PAT for the download step' {
        $env:ENTRAOPS_PAT = 'test-pat'

        & (Join-Path $EntryRoot 'Prepare-EntraOpsAdoUpdate.ps1') -SourceCommit ('b' * 40) -PublisherPath $State.PublisherPath

        $State.TokenAtDownload | Should -BeExactly 'test-pat'
    }

    It 'passes true and false validation results to the module unchanged' -ForEach @(
        @{ ValidationRequired = $true; BrowserTestsValidated = $true }
        @{ ValidationRequired = $true; BrowserTestsValidated = $false }
        @{ ValidationRequired = $false; BrowserTestsValidated = $false }
    ) {
        $State.ExpectedValidationRequired = $ValidationRequired
        $State.ExpectedBrowserTestsValidated = $BrowserTestsValidated
        & (Join-Path $EntryRoot 'Install-EntraOpsAdoUpdate.ps1') -ConfigFile './custom.json' -SourceCommit ('c' * 40) `
            -ValidationRequired:$ValidationRequired -BrowserTestsValidated:$BrowserTestsValidated

        Should -Invoke Install-EntraOpsUpdateCandidate -Times 1 -Exactly -ParameterFilter {
            $ConfigFile -eq './custom.json' -and $SourceCommit -eq ('c' * 40) -and
            $ValidationRequired -eq $State.ExpectedValidationRequired -and $BrowserTestsValidated -eq $State.ExpectedBrowserTestsValidated
        }
    }
}

Describe 'Azure DevOps trusted validation artifact' -Skip:(-not $HasAdoScripts) {
    BeforeAll {
        function Get-EntraOpsUpdateCandidate { param($ConfigFile, $DestinationPath, $ArchivePath) }
        function Get-EntraOpsUpdatePlan { param($Repository, $SourceCommit, $TargetUpdateFolders, $ValidationFrequency, [switch]$RunBrowserTests, [switch]$Force) }
    }

    BeforeEach {
        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $PipelineScripts = Join-Path $Root '.azure-pipelines/scripts'
        $Validators = Join-Path $Root '.github/scripts'
        $Artifact = Join-Path $Root 'artifact'
        New-Item -ItemType Directory -Path $PipelineScripts, $Validators -Force | Out-Null
        foreach ($Name in 'Resolve-EntraOpsAdoUpdate.ps1', 'Ado-GitAuth.ps1', 'Install-EntraOpsUpdateValidationDependencies.ps1') {
            Copy-Item -LiteralPath (Join-Path $script:ScriptRoot $Name) -Destination $PipelineScripts
        }
        foreach ($Name in 'Test-EntraOpsUpdateCandidate.ps1', 'Test-GitHubActionReferences.ps1') {
            Set-Content -LiteralPath (Join-Path $Validators $Name) -Value "# trusted $Name"
        }
        $ConfigPath = Join-Path $Root 'config.json'
        Set-Content -LiteralPath $ConfigPath -Value '{"AutomatedEntraOpsUpdate":{"ApplyAutomatedEntraOpsUpdate":true}}'
        $State = @{ ValidationRequired = $true }
        Mock Import-Module {} -ParameterFilter { $Name -like '*EntraOps.psd1' }
        Mock Get-EntraOpsUpdateCandidate {
            [pscustomobject]@{ Repository = 'Cloud-Architekt/EntraOps'; SourceCommit = ('a' * 40); ArchiveSha256 = ('b' * 64); TargetUpdateFolders = @('./EntraOps') }
        }
        Mock Get-EntraOpsUpdatePlan {
            [pscustomobject]@{ UpdateRequired = $true; ValidationRequired = $State.ValidationRequired; RunBrowserTests = $true; Reason = 'Test update' }
        }
        $Resolve = {
            & (Join-Path $PipelineScripts 'Resolve-EntraOpsAdoUpdate.ps1') -ConfigFile $ConfigPath `
                -ArchivePath (Join-Path $Root 'candidate.tar') -TrustedValidatorPath $Artifact 6>$null
        }
    }

    AfterEach {
        [Environment]::SetEnvironmentVariable('ENTRAOPS_PAT', $script:SavedEnvironment['ENTRAOPS_PAT'])
    }

    It 'packages the pipeline installer with older deployment validators' {
        Test-Path -LiteralPath (Join-Path $Validators 'Install-EntraOpsUpdateValidationDependencies.ps1') | Should -BeFalse

        & $Resolve

        foreach ($Name in 'Test-EntraOpsUpdateCandidate.ps1', 'Test-GitHubActionReferences.ps1') {
            Get-Content -LiteralPath (Join-Path $Artifact $Name) -Raw | Should -BeExactly (Get-Content -LiteralPath (Join-Path $Validators $Name) -Raw)
        }
        Get-Content -LiteralPath (Join-Path $Artifact 'Install-EntraOpsUpdateValidationDependencies.ps1') -Raw |
            Should -BeExactly (Get-Content -LiteralPath (Join-Path $PipelineScripts 'Install-EntraOpsUpdateValidationDependencies.ps1') -Raw)
    }

    It 'uses the pipeline installer even when the deployment has an older copy' {
        Set-Content -LiteralPath (Join-Path $Validators 'Install-EntraOpsUpdateValidationDependencies.ps1') -Value '# old installer'

        & $Resolve

        Get-Content -LiteralPath (Join-Path $Artifact 'Install-EntraOpsUpdateValidationDependencies.ps1') -Raw |
            Should -BeExactly (Get-Content -LiteralPath (Join-Path $PipelineScripts 'Install-EntraOpsUpdateValidationDependencies.ps1') -Raw)
    }

    It 'reports a missing trusted script before publishing validation outputs' -ForEach @(
        @{ Missing = '.github/scripts/Test-EntraOpsUpdateCandidate.ps1' }
        @{ Missing = '.github/scripts/Test-GitHubActionReferences.ps1' }
        @{ Missing = '.azure-pipelines/scripts/Install-EntraOpsUpdateValidationDependencies.ps1' }
    ) {
        Remove-Item -LiteralPath (Join-Path $Root $Missing)

        { & $Resolve } | Should -Throw '*Required trusted validation script*is missing*'
        Test-Path -LiteralPath $Artifact | Should -BeFalse
    }

    It 'does not require validation scripts when validation is disabled' {
        $State.ValidationRequired = $false
        Remove-Item -LiteralPath $Validators -Recurse

        { & $Resolve } | Should -Not -Throw
        Test-Path -LiteralPath $Artifact | Should -BeFalse
    }
}

Describe 'Azure DevOps validation dependencies' -Skip:(-not $HasAdoScripts) {
    It 'installs the latest available modules without version constraints' {
        Mock Install-Module {}

        & (Join-Path $script:ScriptRoot 'Install-EntraOpsUpdateValidationDependencies.ps1')

        Should -Invoke Install-Module -Times 2 -Exactly
        foreach ($ModuleName in 'Pester', 'powershell-yaml') {
            Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter {
                $Name -eq $ModuleName -and $Scope -eq 'CurrentUser' -and $Force -and $Repository -eq 'PSGallery' -and
                -not $MinimumVersion -and -not $MaximumVersion -and -not $RequiredVersion
            }
        }
    }
}

Describe 'Publish-EntraOpsAdoUpdate' -Skip:(-not $HasAdoScripts -or -not $HasGit) {
    BeforeAll {
        $script:SourceCommit = 'a' * 40
        $script:UpdateRef = "refs/heads/entraops/update-$('a' * 12)"
    }

    BeforeEach {
        $env:SYSTEM_COLLECTIONURI = 'https://dev.azure.com/contoso/'
        # Mock bodies resolve $script: to the script under test, so state is shared through this hashtable
        $State = @{ Visibility = 'private'; ActivePullRequests = @(); CreatedPullRequests = [System.Collections.Generic.List[object]]::new() }
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/_apis/projects/*' } { [pscustomobject]@{ name = 'Identity'; visibility = $State.Visibility } }
        Mock Invoke-RestMethod -ParameterFilter { $Method -eq 'Get' -and $Uri -like '*/pullrequests?*' } { [pscustomobject]@{ value = $State.ActivePullRequests } }
        Mock Invoke-RestMethod -ParameterFilter { $Method -eq 'Post' -and $Uri -like '*/pullrequests?*' } {
            $State.CreatedPullRequests.Add(($Body | ConvertFrom-Json))
            [pscustomobject]@{ pullRequestId = 42; title = 'Update EntraOps' }
        }

        $script:Repository = New-TestRepository -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString()))
        Set-Content -LiteralPath (Join-Path $script:Repository.Clone 'README.md') -Value 'applied update'
        $script:Publish = {
            Push-Location -LiteralPath $script:Repository.Clone
            try {
                & (Join-Path $script:ScriptRoot 'Publish-EntraOpsAdoUpdate.ps1') -SourceCommit $script:SourceCommit -ValidationRequired $true -BrowserTests $true `
                    -SourceBranch 'refs/heads/main' -AccessToken 'secret-token' -ProjectId 'project-id' -RepositoryId 'repository-id' -BuildId '17' 6>$null
            } finally {
                Pop-Location
            }
        }
    }

    It 'pushes the update branch based on the current main and creates a pull request' {
        $MainCommit = Add-RemoteCommit -Remote $script:Repository.Remote -Root $TestDrive

        & $script:Publish

        $BranchCommit = ([string](Invoke-TestBareGit -Path $script:Repository.Remote rev-parse $script:UpdateRef)).Trim()
        ([string](Invoke-TestBareGit -Path $script:Repository.Remote rev-parse "$BranchCommit^")).Trim() | Should -Be $MainCommit
        ([string](Invoke-TestBareGit -Path $script:Repository.Remote show "$($BranchCommit):README.md")).Trim() | Should -Be 'applied update'
        $State.CreatedPullRequests.Count | Should -Be 1
        $State.CreatedPullRequests[0].sourceRefName | Should -Be $script:UpdateRef
        $State.CreatedPullRequests[0].targetRefName | Should -Be 'refs/heads/main'
        $State.CreatedPullRequests[0].description | Should -Match 'isolated validation job \(Pester and browser tests\)'
        Get-Content -LiteralPath (Join-Path $script:Repository.Clone '.git/config') -Raw | Should -Not -Match 'secret-token'
    }

    It 'leaves the branch of an active pull request unchanged so review commits are kept' {
        $ReviewCommit = Add-RemoteCommit -Remote $script:Repository.Remote -Root $TestDrive
        Invoke-TestBareGit -Path $script:Repository.Remote update-ref $script:UpdateRef $ReviewCommit | Out-Null
        $State.ActivePullRequests = @([pscustomobject]@{ pullRequestId = 7 })

        & $script:Publish

        ([string](Invoke-TestBareGit -Path $script:Repository.Remote rev-parse $script:UpdateRef)).Trim() | Should -Be $ReviewCommit
        $State.CreatedPullRequests.Count | Should -Be 0
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter { $Method -eq 'Post' }
    }

    It 'replaces a branch left from a closed pull request' {
        $OldCommit = Add-RemoteCommit -Remote $script:Repository.Remote -Root $TestDrive
        Invoke-TestBareGit -Path $script:Repository.Remote update-ref $script:UpdateRef $OldCommit | Out-Null
        Invoke-TestBareGit -Path $script:Repository.Remote update-ref refs/heads/main "$OldCommit^" | Out-Null

        & $script:Publish

        $BranchCommit = ([string](Invoke-TestBareGit -Path $script:Repository.Remote rev-parse $script:UpdateRef)).Trim()
        $BranchCommit | Should -Not -Be $OldCommit
        ([string](Invoke-TestBareGit -Path $script:Repository.Remote show "$($BranchCommit):README.md")).Trim() | Should -Be 'applied update'
        $State.CreatedPullRequests.Count | Should -Be 1
    }

    It 'refuses to publish from a project that is not private' {
        $State.Visibility = 'public'

        { & $script:Publish } | Should -Throw '*is not private*'

        & git --git-dir $script:Repository.Remote rev-parse --verify --quiet $script:UpdateRef | Out-Null
        $LASTEXITCODE | Should -Not -Be 0
        $State.CreatedPullRequests.Count | Should -Be 0
    }
}

Describe 'Resolve-EntraOpsAdoUpdate' -Skip:(-not $HasAdoScripts) {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../../EntraOps/EntraOps.psd1') -Force
    }

    BeforeEach {
        $script:ConfigPath = Join-Path $TestDrive 'EntraOpsConfig.json'
        # Mock bodies resolve $script: to the script under test, so state is shared through this hashtable
        $State = @{ Targets = @('./EntraOps', './.azure-pipelines', './.github/scripts'); PatSeenByCandidate = 'unset' }
        $script:SetConfig = {
            param ([bool]$Enabled = $true, [string]$Frequency = 'OnChange')
            @{ AutomatedEntraOpsUpdate = @{ ApplyAutomatedEntraOpsUpdate = $Enabled; ValidationFrequency = $Frequency; RunBrowserTests = $false; PublicationMode = 'PullRequest' } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ConfigPath
        }
        Mock Import-Module {} -ParameterFilter { $Name -like '*EntraOps.psd1' }
        Mock Get-EntraOpsUpdateCandidate {
            $State.PatSeenByCandidate = [Environment]::GetEnvironmentVariable('ENTRAOPS_PAT')
            [pscustomobject]@{ Repository = 'Cloud-Architekt/EntraOps'; SourceCommit = 'b' * 40; ArchiveSha256 = 'c' * 64; TargetUpdateFolders = $State.Targets }
        }
        Mock Get-EntraOpsUpdatePlan { [pscustomobject]@{ UpdateRequired = $true; ValidationRequired = ($ValidationFrequency -ne 'Never'); RunBrowserTests = $false; Reason = 'Changed.' } }
        $script:Resolve = {
            param ([string]$Pat)
            $env:ENTRAOPS_PAT = $Pat
            (& (Join-Path $script:ScriptRoot 'Resolve-EntraOpsAdoUpdate.ps1') -ConfigFile $script:ConfigPath `
                -DestinationPath (Join-Path $TestDrive 'TmpUpdate') -ArchivePath (Join-Path $TestDrive 'candidate.tar') `
                -TrustedValidatorPath (Join-Path $TestDrive 'trusted-validators') 6>&1 3>$null) |
            ForEach-Object { "$_" }
        }
    }

    It 'sets the output variables of the resolved candidate' {
        & $script:SetConfig

        $Output = & $script:Resolve 'pat-value'

        $Output | Should -Contain "##vso[task.setvariable variable=source_sha;isOutput=true]$('b' * 40)"
        $Output | Should -Contain "##vso[task.setvariable variable=candidate_digest;isOutput=true]$('c' * 64)"
        $Output | Should -Contain '##vso[task.setvariable variable=update_required;isOutput=true]true'
        $Output | Should -Contain '##vso[task.setvariable variable=validation_required;isOutput=true]true'
        $State.PatSeenByCandidate | Should -Be 'pat-value'
    }

    It 'does not resolve a candidate when automated updates are disabled' {
        & $script:SetConfig -Enabled $false

        $Output = & $script:Resolve ''

        $Output | Should -Contain '##vso[task.setvariable variable=update_required;isOutput=true]false'
        Should -Invoke Get-EntraOpsUpdateCandidate -Times 0 -Exactly
    }

    It 'requires validation when the pipeline definitions are updated, even with ValidationFrequency Never' {
        & $script:SetConfig -Frequency 'Never'

        $Output = & $script:Resolve ''

        $Output | Should -Contain '##vso[task.setvariable variable=validation_required;isOutput=true]true'
    }

    It 'skips validation with ValidationFrequency Never when the pipeline definitions are not updated' {
        & $script:SetConfig -Frequency 'Never'
        $State.Targets = @('./EntraOps')

        $Output = & $script:Resolve ''

        $Output | Should -Contain '##vso[task.setvariable variable=validation_required;isOutput=true]false'
    }

    It 'does not pass an undefined EntraOpsUpdatePat macro as a token' {
        & $script:SetConfig

        & $script:Resolve '$(EntraOpsUpdatePat)' | Out-Null

        $State.PatSeenByCandidate | Should -BeNullOrEmpty
    }
}
