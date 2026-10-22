function Get-EntraOpsUpdateCandidate {
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = './EntraOpsConfig.json',

    [Parameter(Mandatory = $true)]
    [string]$DestinationPath,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedSourceCommit,

    [Parameter(Mandatory = $false)]
    [string]$ArchivePath,

    # Return the resolved source parameters without cloning; used by tests and dry runs.
    [Parameter(Mandatory = $false)]
    [switch]$ResolveOnly
)

$ErrorActionPreference = 'Stop'

# Must stay identical to the defaults in Update-EntraOps and New-EntraOpsConfigFile. The public
# release repository needs no credentials; EntraOps-Insiders is private and requires
# EntraOpsUpdatePat. Which repositories exist and whether they need a token is declared once in the
# local EntraOpsUpdateContract.json and resolved by Resolve-EntraOpsUpdateSource.
$DefaultRepositoryName = 'EntraOps'
$DefaultBranch = 'main'
$DefaultTargetUpdateFolders = @('./.github/actions', './.github/agents', './.github/scripts', './Docs', './EntraOps', './Parsers', './Queries', './Reports', './Samples', './Tests', './Workbooks', './package.json', './package-lock.json', './playwright.config.mjs', './CHANGELOG.md', './EntraOpsUpdateContract.json')

$Config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json -ErrorAction Stop
$UpdateConfig = $Config.AutomatedEntraOpsUpdate
$MissingConfigKeys = [System.Collections.Generic.List[string]]::new()

# Configurations generated before these keys existed fall back to the same defaults as Update-EntraOps.
$RepositoryName = [string]$UpdateConfig.Repository
if ([string]::IsNullOrWhiteSpace($RepositoryName)) {
    $RepositoryName = $DefaultRepositoryName
    $MissingConfigKeys.Add("Repository (using '$DefaultRepositoryName')")
}
$ConfiguredBranch = [string]$UpdateConfig.Branch
if ([string]::IsNullOrWhiteSpace($ConfiguredBranch)) {
    $ConfiguredBranch = $DefaultBranch
    $MissingConfigKeys.Add("Branch (using '$DefaultBranch')")
}
$RequestedRef = if ($ExpectedSourceCommit) { $ExpectedSourceCommit } else { $ConfiguredBranch }
$TargetUpdateFolders = @($UpdateConfig.TargetUpdateFolders | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($TargetUpdateFolders.Count -eq 0) {
    $TargetUpdateFolders = $DefaultTargetUpdateFolders
    $MissingConfigKeys.Add('TargetUpdateFolders (using the built-in default targets)')
}
if ($MissingConfigKeys.Count -gt 0) {
    Write-Warning "AutomatedEntraOpsUpdate in '$ConfigFile' does not define: $($MissingConfigKeys -join '; '). Add these keys to make the update source explicit."
}

if ($RepositoryName -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "Unsupported automated-update repository name '$RepositoryName'."
}
if ([string]::IsNullOrWhiteSpace($RequestedRef) -or $RequestedRef.StartsWith('-') -or $RequestedRef -match '\s') {
    throw "Unsupported automated-update ref '$RequestedRef'."
}
if ($TargetUpdateFolders.Count -eq 0) {
    throw 'AutomatedEntraOpsUpdate.TargetUpdateFolders must contain at least one target.'
}
if ($TargetUpdateFolders -contains './.github/workflows') {
    $MissingWorkflowDependencies = @(@('./.github/actions', './.github/scripts') | Where-Object { $TargetUpdateFolders -notcontains $_ })
    if ($MissingWorkflowDependencies.Count -gt 0) {
        throw "Updating './.github/workflows' also requires target(s): $($MissingWorkflowDependencies -join ', ')."
    }
}

$Source = Resolve-EntraOpsUpdateSource -Repository $RepositoryName
$Repository = $Source.Repository
$PersonalAccessToken = [string]$env:ENTRAOPS_PAT
$UsePersonalAccessToken = $false
if ($Source.RequiresPersonalAccessToken) {
    $UsePersonalAccessToken = -not [string]::IsNullOrWhiteSpace($PersonalAccessToken)
} elseif (-not [string]::IsNullOrWhiteSpace($PersonalAccessToken)) {
    if ($Source.IsKnownDistributionRepository) {
        # The public release repository is cloned anonymously so the token is never sent where it is not needed.
        Write-Verbose "Update source '$Repository' is public. The provided Personal Access Token is not used."
    } else {
        $UsePersonalAccessToken = $true
    }
}

if ($ResolveOnly) {
    return [pscustomobject]@{
        Repository                  = $Repository
        RequestedRef                = $RequestedRef
        TargetUpdateFolders         = @($TargetUpdateFolders)
        MissingConfigKeys           = @($MissingConfigKeys)
        Channel                     = $Source.Channel
        RequiresPersonalAccessToken = [bool]$Source.RequiresPersonalAccessToken
        UsesPersonalAccessToken     = $UsePersonalAccessToken
    }
}
if ($Source.RequiresPersonalAccessToken -and -not $UsePersonalAccessToken) {
    throw "Update source '$Repository' is a private distribution repository and requires a Personal Access Token. Configure the 'EntraOpsUpdatePat' repository secret, or set AutomatedEntraOpsUpdate.Repository to the public 'EntraOps' release repository."
}
$DestinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationPath)
if (Test-Path -LiteralPath $DestinationPath) {
    throw "Candidate destination '$DestinationPath' already exists."
}

$RepositoryUrl = $Source.RepositoryUrl
$PreviousConfigCount = $env:GIT_CONFIG_COUNT
$PreviousConfigKey0 = $env:GIT_CONFIG_KEY_0
$PreviousConfigValue0 = $env:GIT_CONFIG_VALUE_0
try {
    if ($UsePersonalAccessToken) {
        Write-Output "Cloning '$Repository' ($($Source.Channel) channel) using the Personal Access Token..."
        $env:GIT_CONFIG_COUNT = '1'
        $env:GIT_CONFIG_KEY_0 = 'http.https://github.com/.extraheader'
        $env:GIT_CONFIG_VALUE_0 = "AUTHORIZATION: basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$PersonalAccessToken")))"
    } else {
        Write-Output "Cloning '$Repository' ($($Source.Channel) channel) without authentication..."
    }
    & git clone --filter=blob:none --no-checkout -- $RepositoryUrl $DestinationPath
    if ($LASTEXITCODE -ne 0) { throw "git clone failed with exit code $LASTEXITCODE." }
    & git -C $DestinationPath fetch --depth 1 origin -- $RequestedRef
    if ($LASTEXITCODE -ne 0) { throw "git fetch failed for '$Repository@$RequestedRef' with exit code $LASTEXITCODE." }
    & git -C $DestinationPath checkout --detach FETCH_HEAD
    if ($LASTEXITCODE -ne 0) { throw "git checkout failed for '$Repository@$RequestedRef' with exit code $LASTEXITCODE." }
} finally {
    if ($null -eq $PreviousConfigCount) { Remove-Item env:GIT_CONFIG_COUNT -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_COUNT = $PreviousConfigCount }
    if ($null -eq $PreviousConfigKey0) { Remove-Item env:GIT_CONFIG_KEY_0 -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_KEY_0 = $PreviousConfigKey0 }
    if ($null -eq $PreviousConfigValue0) { Remove-Item env:GIT_CONFIG_VALUE_0 -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_VALUE_0 = $PreviousConfigValue0 }
}

$SourceCommit = (& git -C $DestinationPath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $SourceCommit -notmatch '^[0-9a-fA-F]{40}$') {
    throw 'Could not resolve the immutable source commit.'
}
if ($ExpectedSourceCommit -and $SourceCommit -ne $ExpectedSourceCommit) {
    throw "Resolved source commit '$SourceCommit' does not match validated commit '$ExpectedSourceCommit'."
}

Test-EntraOpsUpdateContract -CandidateRoot $DestinationPath -Repository $Repository -TargetUpdateFolders $TargetUpdateFolders | Out-Null

if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) {
    $ArchivePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ArchivePath)
    & git -C $DestinationPath archive --format=tar --output=$ArchivePath HEAD
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "Could not archive update candidate '$Repository@$SourceCommit'."
    }
    $ArchiveSha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
}

[pscustomobject]@{
    Repository                  = $Repository
    RequestedRef                = $RequestedRef
    SourceCommit                = $SourceCommit
    TargetUpdateFolders         = @($TargetUpdateFolders)
    CandidatePath               = $DestinationPath
    ArchivePath                 = if ($ArchivePath) { $ArchivePath } else { $null }
    ArchiveSha256               = if ($ArchivePath) { $ArchiveSha256 } else { $null }
    Channel                     = $Source.Channel
    RequiresPersonalAccessToken = [bool]$Source.RequiresPersonalAccessToken
    UsesPersonalAccessToken     = $UsePersonalAccessToken
}
}
