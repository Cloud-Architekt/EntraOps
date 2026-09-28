<#
.SYNOPSIS
    Update of EntraOps PowerShell module and GitHub workflow files.

.DESCRIPTION
    Cmdlet is used to update the EntraOps PowerShell module and GitHub workflow files.
    If the config file's "AutomatedEntraOpsUpdate" section defines "Repository", "Branch" and/or
    "TargetUpdateFolders", those values are used instead of the built-in defaults, unless the
    corresponding -Repository, -Branch or -TargetUpdateFolders parameter is explicitly passed to
    this cmdlet. GitHub workflow definitions are excluded from the default targets. To update them
    interactively, explicitly select ./.github/workflows together with ./.github/actions and
    ./.github/scripts, then publish the reviewed local changes with an authorized user credential.

    The supported distribution repositories are declared once in the local EntraOpsUpdateContract.json:
    the public "EntraOps" release repository (default, no credentials) and the private
    "EntraOps-Insiders" repository, which requires -PersonalAccessToken or the ENTRAOPS_PAT
    environment variable (the EntraOpsUpdatePat secret in the workflow).

.PARAMETER TargetUpdateFolders
    Repository-relative targets to replace from the configured upstream ref. Workflow definitions
    are supported but excluded by default. Select ./.github/workflows together with
    ./.github/actions and ./.github/scripts for an interactive workflow refresh. Automated workflow
    publication additionally requires the GitHub App credentials documented in Docs/content/core.md.

.EXAMPLE
    This example updates EntraOps with default values of the main branch and the default target folders.
    Update-EntraOps

.EXAMPLE
    This example explicitly refreshes GitHub workflow definitions and their required dependencies.
    Update-EntraOps -ConfigFile ./EntraOpsConfig.json -RunBrowserTests `
        -TargetUpdateFolders @('./.github/actions', './.github/scripts', './.github/workflows')
#>

function Update-EntraOps {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$Branch = "main"
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$Repository = "EntraOps"
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$UpstreamUrl
        ,        
        [Parameter(Mandatory = $False)]
        [System.String]$PersonalAccessToken
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$ConfigFile = "./EntraOpsConfig.json"
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("./.github/actions", "./.github/agents", "./.github/scripts", "./.github/workflows", "./Docs", "./EntraOps", "./Parsers", "./Queries", "./Reports", "./Samples", "./Tests", "./Workbooks", "./package.json", "./package-lock.json", "./playwright.config.mjs", "./CHANGELOG.md", "./EntraOpsUpdateContract.json")]
        [Object]$TargetUpdateFolders = @("./.github/actions", "./.github/agents", "./.github/scripts", "./Docs", "./EntraOps", "./Parsers", "./Queries", "./Reports", "./Samples", "./Tests", "./Workbooks", "./package.json", "./package-lock.json", "./playwright.config.mjs", "./CHANGELOG.md", "./EntraOpsUpdateContract.json")
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$TemporaryUpdateFolder = "TmpUpdate"
        ,
        [Parameter(Mandatory = $False)]
        [switch]$RunBrowserTests
        ,
        [Parameter(Mandatory = $False)]
        [switch]$SkipCandidateValidation
        ,
        [Parameter(Mandatory = $False)]
        [string]$PreparedCandidatePath
        ,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$ValidatedSourceCommit
        ,
        [Parameter(Mandatory = $False)]
        [switch]$BrowserTestsValidated
    )

    $ErrorActionPreference = "Stop"

    # Allow the config file's "AutomatedEntraOpsUpdate" section to override the default
    # Repository/Branch/TargetUpdateFolders used for self-update, unless the caller explicitly
    # passed -Repository, -Branch or -TargetUpdateFolders.
    if (Test-Path -Path $ConfigFile) {
        try {
            $UpdateConfig = (Get-Content -Path $ConfigFile | ConvertFrom-Json).AutomatedEntraOpsUpdate
            if (-not $PSBoundParameters.ContainsKey('Repository') -and -not [string]::IsNullOrWhiteSpace($UpdateConfig.Repository)) {
                Write-Verbose "Using Repository '$($UpdateConfig.Repository)' from config file '$ConfigFile'."
                $Repository = $UpdateConfig.Repository
            }
            if (-not $PSBoundParameters.ContainsKey('Branch') -and -not [string]::IsNullOrWhiteSpace($UpdateConfig.Branch)) {
                Write-Verbose "Using Branch '$($UpdateConfig.Branch)' from config file '$ConfigFile'."
                $Branch = $UpdateConfig.Branch
            }
            if (-not $PSBoundParameters.ContainsKey('TargetUpdateFolders') -and $UpdateConfig.TargetUpdateFolders) {
                Write-Verbose "Using TargetUpdateFolders '$($UpdateConfig.TargetUpdateFolders -join ', ')' from config file '$ConfigFile'."
                $TargetUpdateFolders = @($UpdateConfig.TargetUpdateFolders)
            }
        } catch {
            Write-Warning "Failed to read Repository/Branch/TargetUpdateFolders override from config file '$ConfigFile'. Falling back to defaults. Error: $_"
        }
    }

    # Validate config-derived targets explicitly. ValidateSet protects command-line arguments, but
    # values read from JSON bypass parameter binding and must not escape the intended repository
    # update boundary.
    $AllowedUpdateTargets = @('./.github/actions', './.github/agents', './.github/scripts', './.github/workflows', './Docs', './EntraOps', './Parsers', './Queries', './Reports', './Samples', './Tests', './Workbooks', './package.json', './package-lock.json', './playwright.config.mjs', './CHANGELOG.md', './EntraOpsUpdateContract.json')
    $TargetUpdateFolders = @($TargetUpdateFolders | ForEach-Object { [string]$_ } | Select-Object -Unique)
    if ($TargetUpdateFolders.Count -eq 0) {
        throw 'At least one TargetUpdateFolders entry is required.'
    }
    $InvalidUpdateTargets = @($TargetUpdateFolders | Where-Object { $AllowedUpdateTargets -notcontains $_ })
    if ($InvalidUpdateTargets.Count -gt 0) {
        throw "Unsupported TargetUpdateFolders value(s) in '$ConfigFile': $($InvalidUpdateTargets -join ', '). Use only repository targets exposed by Update-EntraOps."
    }
    if ($TargetUpdateFolders -contains './.github/workflows') {
        $MissingWorkflowDependencies = @(@('./.github/actions', './.github/scripts') | Where-Object { $TargetUpdateFolders -notcontains $_ })
        if ($MissingWorkflowDependencies.Count -gt 0) {
            throw "Updating './.github/workflows' also requires target(s): $($MissingWorkflowDependencies -join ', ')."
        }
        if ($SkipCandidateValidation) {
            throw "Candidate validation cannot be skipped when './.github/workflows' is updated."
        }
    }
    if ([string]::IsNullOrWhiteSpace($Branch) -or $Branch.StartsWith('-') -or $Branch -match '\s') {
        throw "Unsupported automated-update ref '$Branch'. Use a branch, release tag, or full commit SHA without whitespace or a leading dash."
    }
    if ($ValidatedSourceCommit -and -not $PreparedCandidatePath) {
        throw '-ValidatedSourceCommit requires -PreparedCandidatePath. Resolve and validate the candidate in a separate, credential-free job before applying it.'
    }

    if ([string]::IsNullOrWhiteSpace($PersonalAccessToken) -and -not [string]::IsNullOrWhiteSpace($env:ENTRAOPS_PAT)) {
        $PersonalAccessToken = $env:ENTRAOPS_PAT
    }
    $UsePersonalAccessToken = $false

    if (-not [string]::IsNullOrWhiteSpace($UpstreamUrl)) {
        $SourceRepository = $UpstreamUrl
        $UsePersonalAccessToken = -not [string]::IsNullOrWhiteSpace($PersonalAccessToken)
    } else {
        # The local contract is the single source of truth for which Cloud-Architekt repositories
        # distribute EntraOps and whether they need a Personal Access Token. Resolving it here, before
        # any clone, keeps the credential decision independent of the downloaded candidate.
        $Source = Resolve-EntraOpsUpdateSource -Repository $Repository -ContractPath (Join-Path $EntraOpsBaseFolder 'EntraOpsUpdateContract.json')
        $SourceRepository = $Source.Repository
        if ($Source.RequiresPersonalAccessToken) {
            if ([string]::IsNullOrWhiteSpace($PersonalAccessToken) -and [string]::IsNullOrWhiteSpace($PreparedCandidatePath)) {
                throw "Update source '$SourceRepository' is a private distribution repository and requires a Personal Access Token. Pass -PersonalAccessToken, set ENTRAOPS_PAT (the EntraOpsUpdatePat secret), or use the public 'EntraOps' release repository. No local folder was changed."
            }
            $UsePersonalAccessToken = -not [string]::IsNullOrWhiteSpace($PersonalAccessToken)
        } elseif (-not [string]::IsNullOrWhiteSpace($PersonalAccessToken)) {
            if ($Source.IsKnownDistributionRepository) {
                Write-Verbose "Update source '$SourceRepository' is public. The provided Personal Access Token is not used."
            } else {
                $UsePersonalAccessToken = $true
            }
        }
    }

    # A branch name is mutable: whatever is on it at run time is installed and executed. Release tags
    # and full commit SHAs are immutable and are the supported choice for scheduled, unattended updates.
    if ($Branch -notmatch '^[0-9a-fA-F]{40}$' -and $Branch -notmatch '^v?\d+\.\d+') {
        Write-Warning "EntraOps is updated from the mutable ref '$Branch'. Any upstream commit is installed and executed on the next run without review. Pin 'AutomatedEntraOpsUpdate.Branch' in $ConfigFile to a release tag or a full commit SHA for unattended updates."
    }

    $CloneUpdateCandidate = {
        param([string]$RepositoryUrl)
        & git clone --filter=blob:none --no-checkout $RepositoryUrl $TemporaryUpdateFolder
        if ($LASTEXITCODE -ne 0) {
            throw "git clone failed with exit code $LASTEXITCODE. Verify the repository name and whether a Personal Access Token (secret: EntraOpsUpdatePat) is required."
        }
        & git -C $TemporaryUpdateFolder fetch --depth 1 origin -- $Branch
        if ($LASTEXITCODE -ne 0) {
            throw "git fetch failed for requested ref '$Branch' with exit code $LASTEXITCODE. Use an advertised branch, release tag, or reachable full commit SHA."
        }
        & git -C $TemporaryUpdateFolder checkout --detach FETCH_HEAD
        if ($LASTEXITCODE -ne 0) {
            throw "git checkout failed for requested ref '$Branch' with exit code $LASTEXITCODE."
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($UpstreamUrl)) {
        $RepositoryUrl = $UpstreamUrl
    } else {
        $RepositoryUrl = $Source.RepositoryUrl
    }

    # Resolve relative paths against the PowerShell location. Set-Location does not move
    # [Environment]::CurrentDirectory, so [System.IO.Path]::GetFullPath would otherwise point at the
    # directory pwsh was started in while git clones into $PWD.
    $OwnCandidateCheckout = [string]::IsNullOrWhiteSpace($PreparedCandidatePath)
    if ($OwnCandidateCheckout) {
        $TemporaryUpdateFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TemporaryUpdateFolder)
    } else {
        $TemporaryUpdateFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PreparedCandidatePath)
    }

    try {
        if (-not $OwnCandidateCheckout) {
            if (-not (Test-Path -LiteralPath $TemporaryUpdateFolder -PathType Container)) {
                throw "Prepared update candidate '$TemporaryUpdateFolder' does not exist. No local file was changed."
            }
            Write-Output "Using prepared update candidate at '$TemporaryUpdateFolder'."
        } elseif ($UsePersonalAccessToken) {
            $ChannelLabel = if ($null -ne $Source) { "$($Source.Channel) channel" } else { "custom upstream" }
            Write-Output "Cloning repository '$SourceRepository' ($ChannelLabel, ref: $Branch) using Personal Access Token..."
            # Pass credentials via environment-based HTTP header to avoid exposing the PAT in process listings, logs, or error messages
            $PreviousConfigCount = $env:GIT_CONFIG_COUNT
            $PreviousConfigKey0 = $env:GIT_CONFIG_KEY_0
            $PreviousConfigValue0 = $env:GIT_CONFIG_VALUE_0
            $UpstreamHost = if (-not [string]::IsNullOrWhiteSpace($UpstreamUrl)) { ([System.Uri]$UpstreamUrl).Host } else { "github.com" }
            try {
                $env:GIT_CONFIG_COUNT = "1"
                $env:GIT_CONFIG_KEY_0 = "http.https://$UpstreamHost/.extraheader"
                $env:GIT_CONFIG_VALUE_0 = "AUTHORIZATION: basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$PersonalAccessToken")))"
                & $CloneUpdateCandidate $RepositoryUrl
            } finally {
                # Restore previous env state
                if ($null -eq $PreviousConfigCount) { Remove-Item env:GIT_CONFIG_COUNT -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_COUNT = $PreviousConfigCount }
                if ($null -eq $PreviousConfigKey0) { Remove-Item env:GIT_CONFIG_KEY_0 -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_KEY_0 = $PreviousConfigKey0 }
                if ($null -eq $PreviousConfigValue0) { Remove-Item env:GIT_CONFIG_VALUE_0 -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_VALUE_0 = $PreviousConfigValue0 }
            }
        } else {
            $ChannelLabel = if ($null -ne $Source) { "$($Source.Channel) channel" } else { "custom upstream" }
            Write-Output "Cloning repository '$SourceRepository' ($ChannelLabel, ref: $Branch) without authentication..."
            & $CloneUpdateCandidate $RepositoryUrl
        }

        $SourceCommit = (& git -C $TemporaryUpdateFolder rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0 -or $SourceCommit -notmatch '^[0-9a-fA-F]{40}$') {
            throw 'Could not resolve the immutable commit SHA of the downloaded update candidate. No local folder was changed.'
        }

        if ($ValidatedSourceCommit -and $SourceCommit -ne $ValidatedSourceCommit) {
            throw "Prepared candidate commit '$SourceCommit' does not match separately validated commit '$ValidatedSourceCommit'. No local folder was changed."
        }

        Test-EntraOpsUpdateContract -CandidateRoot $TemporaryUpdateFolder -Repository $SourceRepository -TargetUpdateFolders $TargetUpdateFolders | Out-Null

        # The contract validator confirms every requested target exists before anything is removed,
        # so a stale or dishonest source contract cannot leave the deployment partially updated.

        if ($ValidatedSourceCommit) {
            Write-Output "Applying candidate $SourceRepository@$SourceCommit after validation completed in a separate credential-free job."
        } elseif (-not $SkipCandidateValidation) {
            $CandidateValidator = Join-Path $EntraOpsBaseFolder '.github/scripts/Test-EntraOpsUpdateCandidate.ps1'
            if (-not (Test-Path -LiteralPath $CandidateValidator -PathType Leaf)) {
                throw "Trusted update candidate validator not found at '$CandidateValidator'. No local folder was changed."
            }
            Write-Output "Validating update candidate $SourceRepository@$SourceCommit in a child process with a sanitized environment before changing local files..."
            # Allowlist (not denylist) so any credential variable is excluded by construction. The OS/profile
            # entries carry no secrets and are required for pwsh, git and npm to start on Windows.
            $AllowedEnvironmentNames = @(
                'PATH', 'PSModulePath', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP', 'CI',
                'HOME', 'USER', 'USERNAME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA',
                'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'SystemRoot', 'SystemDrive', 'windir',
                'COMSPEC', 'PATHEXT', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'POWERSHELL_TELEMETRY_OPTOUT'
            )
            $SavedEnvironment = @{}
            foreach ($Entry in Get-ChildItem Env:) { $SavedEnvironment[$Entry.Name] = $Entry.Value }
            try {
                foreach ($Entry in Get-ChildItem Env:) { Remove-Item -LiteralPath "Env:$($Entry.Name)" -ErrorAction SilentlyContinue }
                foreach ($Name in $AllowedEnvironmentNames) {
                    if ($SavedEnvironment.ContainsKey($Name)) { Set-Item -LiteralPath "Env:$Name" -Value $SavedEnvironment[$Name] }
                }
                $ValidatorArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $CandidateValidator, '-CandidateRoot', $TemporaryUpdateFolder)
                if ($RunBrowserTests) { $ValidatorArguments += '-RunBrowserTests' }
                & (Get-Process -Id $PID).Path @ValidatorArguments
                if ($LASTEXITCODE -ne 0) { throw "Candidate validation child process failed with exit code $LASTEXITCODE." }
            } finally {
                foreach ($Entry in Get-ChildItem Env:) { Remove-Item -LiteralPath "Env:$($Entry.Name)" -ErrorAction SilentlyContinue }
                foreach ($Name in $SavedEnvironment.Keys) { Set-Item -LiteralPath "Env:$Name" -Value $SavedEnvironment[$Name] }
            }
        } else {
            Write-Warning 'Candidate validation was explicitly skipped. Apply only candidates from a fully trusted source.'
        }

        foreach ($TargetUpdateFolder in $TargetUpdateFolders) {

            if (Test-Path -Path $TargetUpdateFolder) {
                Write-Output "Removing folder $TargetUpdateFolder..."
                try {
                    Remove-Item -Path $TargetUpdateFolder -Force -Recurse
                } catch {
                    throw "Failed to remove folder $($TargetUpdateFolder). Error: $_"
                }
            }

            Write-Output "Updating folder $TargetUpdateFolder..."
            try {
                Copy-item -Path "$($TemporaryUpdateFolder)/$($TargetUpdateFolder)" -Destination "$($TargetUpdateFolder)" -Force -Recurse
            } catch {
                throw "Failed to copy folder $($TemporaryUpdateFolder)/$($TargetUpdateFolder) to $($TargetUpdateFolder). The local folder is now incomplete and must be restored from source control. Error: $_"
            }
        }

        # Do not execute newly downloaded module code in the updater process. In automated runs a
        # later step receives a repository token; in interactive runs the caller can still have a PAT,
        # Azure context or other credentials in its environment. Load the module in a subsequent clean
        # process/session after reviewing the applied diff.
        Write-Output 'Updated module import deferred until a subsequent clean process or session.'

        if ($TargetUpdateFolders -contains './.github/workflows') {
            Write-Host "Re-adding workflow parameters in GitHub workflows after update..."
            try {
                Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigFile
            } catch {
                throw "Failed to update required workflow parameters. Error: $_"
            }
        }

        $UpdateManifest = [ordered]@{
            SchemaVersion        = 1
            Repository           = $SourceRepository
            Channel              = $Source.Channel
            RequestedRef         = $Branch
            SourceCommit         = $SourceCommit
            ValidatedBeforeApply = [bool]($ValidatedSourceCommit -or -not $SkipCandidateValidation)
            ValidationIsolation  = if ($ValidatedSourceCommit) { 'SeparateJob' } elseif ($SkipCandidateValidation) { 'Skipped' } else { 'SanitizedChildProcess' }
            BrowserTestsRun      = [bool]($RunBrowserTests -or $BrowserTestsValidated)
            AppliedDateTime      = (Get-Date).ToUniversalTime().ToString('o')
            TargetUpdateFolders  = @($TargetUpdateFolders)
        }
        $UpdateManifestPath = Join-Path $EntraOpsBaseFolder '.EntraOpsUpdateManifest.json'
        $UpdateManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $UpdateManifestPath -Encoding utf8
    } finally {
        # A caller-supplied -PreparedCandidatePath is left in place for inspection.
        if ($OwnCandidateCheckout -and (Test-Path -Path $TemporaryUpdateFolder)) {
            Write-Output "Cleaning up temporary folder $TemporaryUpdateFolder."
            Remove-Item -Path $TemporaryUpdateFolder -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
}
