#Requires -Version 7.4
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$Paths = @('.'),

    [Parameter(Mandatory = $true)]
    [string]$AccessToken,

    [Parameter(Mandatory = $false)]
    [string]$Repository = $env:GITHUB_REPOSITORY,

    [Parameter(Mandatory = $false)]
    [string]$Actor = $env:GITHUB_ACTOR,

    [Parameter(Mandatory = $false)]
    [string]$CommitMessage = "$env:GITHUB_WORKFLOW #$env:GITHUB_RUN_NUMBER",

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = $env:GITHUB_SERVER_URL
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Repository)) { throw 'GitHub repository name is required.' }
if ([string]::IsNullOrWhiteSpace($AccessToken)) { throw 'A GitHub access token is required.' }
if ([string]::IsNullOrWhiteSpace($ServerUrl)) { $ServerUrl = 'https://github.com' }
$Paths = @($Paths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($Paths.Count -eq 0) { throw 'At least one pathspec is required to publish generated output.' }

# Every variable that carries the token is restored on exit so a persistent host (local shell, other CI
# platforms) does not keep sending the Authorization header after this script returns.
$ManagedEnvironment = @('GH_TOKEN', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1')
$PreviousEnvironment = @{}
foreach ($Name in $ManagedEnvironment) { $PreviousEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name) }
try {
    $env:GH_TOKEN = $AccessToken
    $Private = (& gh api "repos/$Repository" --jq .private).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Failed to read GitHub repository visibility for '$Repository'." }
    if ($Private -ne 'true') {
        throw 'Repository is public - refusing to commit and push generated output because it may contain tenant data.'
    }

    & git config user.email 'EntraOpsGHActions@ghActions.com'
    if ($LASTEXITCODE -ne 0) { throw "git config user.email failed with exit code $LASTEXITCODE." }
    & git config user.name $Actor
    if ($LASTEXITCODE -ne 0) { throw "git config user.name failed with exit code $LASTEXITCODE." }
    $MatchingPaths = @($Paths | Where-Object { (Test-Path -LiteralPath $_) -or @(& git ls-files -- $_).Count -gt 0 })
    if ($MatchingPaths.Count -gt 0 -and $MatchingPaths.Count -lt $Paths.Count) {
        $SkippedPaths = @($Paths | Where-Object { $_ -notin $MatchingPaths })
        Write-Host "::warning::Skipped pathspec(s) without files: $($SkippedPaths -join ' ')"
        $Paths = $MatchingPaths
    }
    & git add --all -- @Paths
    if ($LASTEXITCODE -ne 0) { throw "git add failed for pathspec(s) '$($Paths -join ' ')' with exit code $LASTEXITCODE." }
    # git diff --quiet: 0 = no staged changes, 1 = staged changes, anything else = git error.
    & git diff --cached --quiet
    $DiffExitCode = $LASTEXITCODE
    if ($DiffExitCode -eq 1) {
        & git commit -m $CommitMessage
        if ($LASTEXITCODE -ne 0) { throw "git commit failed with exit code $LASTEXITCODE." }
    } elseif ($DiffExitCode -ne 0) {
        throw "git diff --cached failed with exit code $DiffExitCode."
    }

    $Branch = (& git branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Branch)) {
        throw 'Cannot push generated output from a detached HEAD.'
    }

    $Authorization = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$AccessToken"))
    $ExtraHeaderKey = "http.$($ServerUrl.TrimEnd('/'))/.extraheader"
    $env:GIT_CONFIG_COUNT = '2'
    $env:GIT_CONFIG_KEY_0 = $ExtraHeaderKey
    $env:GIT_CONFIG_VALUE_0 = ''
    $env:GIT_CONFIG_KEY_1 = $ExtraHeaderKey
    $env:GIT_CONFIG_VALUE_1 = "AUTHORIZATION: basic $Authorization"
    & git fetch origin $Branch
    if ($LASTEXITCODE -ne 0) { throw "git fetch failed with exit code $LASTEXITCODE." }
    & git rebase --autostash "origin/$Branch"
    if ($LASTEXITCODE -ne 0) { throw "git rebase failed with exit code $LASTEXITCODE." }
    & git push origin "HEAD:$Branch"
    if ($LASTEXITCODE -ne 0) { throw "git push failed with exit code $LASTEXITCODE." }
} finally {
    foreach ($Name in $ManagedEnvironment) { [Environment]::SetEnvironmentVariable($Name, $PreviousEnvironment[$Name]) }
}
