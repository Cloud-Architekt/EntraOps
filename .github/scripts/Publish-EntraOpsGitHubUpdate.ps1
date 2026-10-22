#Requires -Version 7.4
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)] [string]$ActionsToken,
    [Parameter(Mandatory = $false)] [string]$WorkflowPublishToken,
    [Parameter(Mandatory = $true)] [bool]$WorkflowChanges,
    [Parameter(Mandatory = $true)] [ValidateSet('PullRequest', 'DirectPush')] [string]$PublicationMode,
    [Parameter(Mandatory = $true)] [ValidatePattern('^[0-9a-fA-F]{40}$')] [string]$SourceCommit,
    [Parameter(Mandatory = $true)] [bool]$ValidationRequired,
    [Parameter(Mandatory = $true)] [bool]$BrowserTests,
    [Parameter(Mandatory = $false)] [string]$Repository = $env:GITHUB_REPOSITORY,
    [Parameter(Mandatory = $false)] [string]$Actor = $env:GITHUB_ACTOR,
    [Parameter(Mandatory = $false)] [string]$ServerUrl = $env:GITHUB_SERVER_URL,
    [Parameter(Mandatory = $false)] [string]$RunId = $env:GITHUB_RUN_ID,
    [Parameter(Mandatory = $false)] [string]$WorkflowName = $env:GITHUB_WORKFLOW,
    [Parameter(Mandatory = $false)] [string]$RunNumber = $env:GITHUB_RUN_NUMBER
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ServerUrl)) { $ServerUrl = 'https://github.com' }
if (Test-Path -LiteralPath './TmpUpdate') { throw 'The update candidate folder ./TmpUpdate still exists and must not be published.' }

# Every variable that carries a token is restored on exit so a persistent host does not keep sending
# the Authorization header after this script returns.
$ManagedEnvironment = @('GH_TOKEN', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1')
$PreviousEnvironment = @{}
foreach ($Name in $ManagedEnvironment) { $PreviousEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name) }
try {
    $env:GH_TOKEN = $ActionsToken
    $Private = (& gh api "repos/$Repository" --jq .private).Trim()
    if ($LASTEXITCODE -ne 0 -or $Private -ne 'true') { throw 'Repository is public or its visibility could not be verified; refusing to publish an automated EntraOps update.' }

    $CommitMessage = "$WorkflowName #$RunNumber"
    if ($WorkflowChanges) {
        if ([string]::IsNullOrWhiteSpace($WorkflowPublishToken)) {
            throw 'Workflow files changed, but no publisher token was created. Configure EntraOpsUpdateAppClientId and EntraOpsUpdateAppPrivateKey for a GitHub App with Contents, Workflows, Pull requests, and Commit statuses write permissions.'
        }
        $Token = $WorkflowPublishToken
        $CommitMessage += ' [skip actions]'
    } else {
        $Token = $ActionsToken
    }
    $env:GH_TOKEN = $Token

    & git config user.email 'EntraOpsGHActions@ghActions.com'
    if ($LASTEXITCODE -ne 0) { throw "git config user.email failed with exit code $LASTEXITCODE." }
    & git config user.name $Actor
    if ($LASTEXITCODE -ne 0) { throw "git config user.name failed with exit code $LASTEXITCODE." }
    & git add --all -- .
    if ($LASTEXITCODE -ne 0) { throw "git add failed with exit code $LASTEXITCODE." }
    # git diff --quiet: 0 = no staged changes, 1 = staged changes, anything else = git error.
    & git diff --cached --quiet
    $DiffExitCode = $LASTEXITCODE
    if ($DiffExitCode -eq 1) {
        & git commit -m $CommitMessage
        if ($LASTEXITCODE -ne 0) { throw "git commit failed with exit code $LASTEXITCODE." }
    } elseif ($DiffExitCode -ne 0) {
        throw "git diff --cached failed with exit code $DiffExitCode."
    }

    $BaseBranch = (& git branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($BaseBranch)) { throw 'Cannot publish an automated update from a detached HEAD.' }
    $Authorization = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$Token"))
    $ExtraHeaderKey = "http.$($ServerUrl.TrimEnd('/'))/.extraheader"
    $env:GIT_CONFIG_COUNT = '2'
    $env:GIT_CONFIG_KEY_0 = $ExtraHeaderKey
    $env:GIT_CONFIG_VALUE_0 = ''
    $env:GIT_CONFIG_KEY_1 = $ExtraHeaderKey
    $env:GIT_CONFIG_VALUE_1 = "AUTHORIZATION: basic $Authorization"
    & git fetch origin $BaseBranch
    if ($LASTEXITCODE -ne 0) { throw "git fetch failed with exit code $LASTEXITCODE." }
    & git rebase --autostash "origin/$BaseBranch"
    if ($LASTEXITCODE -ne 0) { throw "git rebase failed with exit code $LASTEXITCODE." }

    $CommitSha = (& git rev-parse HEAD).Trim()
    $RunUrl = "$($ServerUrl.TrimEnd('/'))/$Repository/actions/runs/$RunId"
    $StatusDescription = if ($ValidationRequired) {
        "Candidate validated in an isolated job (browser tests: $($BrowserTests.ToString().ToLowerInvariant()))"
    } else {
        'Candidate validation skipped by configuration (ValidationFrequency Never or manual override)'
    }
    $PostValidationStatus = {
        param([string]$Sha)
        & gh api --method POST "repos/$Repository/statuses/$Sha" -f state=success `
            -f 'context=EntraOps / Update candidate validation' -f "description=$StatusDescription" -f "target_url=$RunUrl" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not post validation status for commit '$Sha'." }
    }

    if ($PublicationMode -eq 'DirectPush') {
        & git push origin "HEAD:$BaseBranch"
        if ($LASTEXITCODE -ne 0) { throw "Direct push failed with exit code $LASTEXITCODE." }
        & $PostValidationStatus $CommitSha
        return
    }

    $UpdateBranch = "entraops/update-$($SourceCommit.Substring(0, 12))"
    # Leave the branch of an open pull request unchanged, so reviewer commits are kept
    $ExistingPullRequests = @(& gh pr list --repo $Repository --state open --base $BaseBranch --head $UpdateBranch --json number | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Could not query existing EntraOps update pull requests.' }
    if ($ExistingPullRequests.Count -gt 0) {
        Write-Host "EntraOps update pull request #$($ExistingPullRequests[0].number) for this candidate is still open. Its branch '$UpdateBranch' was left unchanged."
        return
    }

    # git ls-remote --exit-code: 0 = branch exists, 2 = no matching ref, anything else = git/auth/network error.
    & git ls-remote --exit-code --heads origin $UpdateBranch | Out-Null
    $LsRemoteExitCode = $LASTEXITCODE
    if ($LsRemoteExitCode -eq 0) {
        & git fetch origin "refs/heads/${UpdateBranch}:refs/remotes/origin/$UpdateBranch"
        if ($LASTEXITCODE -ne 0) { throw "Could not fetch existing update branch '$UpdateBranch'." }
        $RemoteUpdateSha = (& git rev-parse "refs/remotes/origin/$UpdateBranch").Trim()
        & git push "--force-with-lease=refs/heads/${UpdateBranch}:$RemoteUpdateSha" origin "HEAD:refs/heads/$UpdateBranch"
    } elseif ($LsRemoteExitCode -eq 2) {
        & git push origin "HEAD:refs/heads/$UpdateBranch"
    } else {
        throw "Could not query the remote for update branch '$UpdateBranch' (git ls-remote exit code $LsRemoteExitCode)."
    }
    if ($LASTEXITCODE -ne 0) { throw "Could not publish update branch '$UpdateBranch'." }
    & $PostValidationStatus $CommitSha

    $ReviewGuidance = if ($WorkflowChanges) {
        'This branch replaces workflow definitions, so its commit carries `[skip actions]` and no repository workflow runs on the branch before review; the isolated validation result above is the trusted check. Review every workflow diff before merging. Test-EntraOps runs on the base branch after the merge.'
    } else {
        'Test-EntraOps runs on this pull request through its `pull_request` trigger. Because the pull request was opened by GitHub Actions, GitHub may hold that run until a maintainer approves it (**Approve and run workflows** on the pull request); a run that is never approved ends without jobs. Wait for it and for the `EntraOps / Update candidate validation` commit status before merging.'
    }
    $Body = "EntraOps update from source commit ``$SourceCommit``. ${StatusDescription}: ${RunUrl}. This branch contains the applied candidate and configuration-restored workflow templates. $ReviewGuidance Recommended: protect the base branch with a ruleset that requires the ``EntraOps / Update candidate validation`` status, which every update pull request receives. Do not make Test-EntraOps a required check: a ``[skip actions]`` commit leaves it pending forever and would block workflow updates."
    & gh pr create --repo $Repository --base $BaseBranch --head $UpdateBranch --title "Update EntraOps to $($SourceCommit.Substring(0, 12))" --body $Body
    if ($LASTEXITCODE -ne 0) {
        throw "Pull request creation failed. The update branch '$UpdateBranch' was pushed. Enable GitHub Actions pull-request creation or verify the GitHub App's Pull requests permission. See https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests"
    }
} finally {
    foreach ($Name in $ManagedEnvironment) { [Environment]::SetEnvironmentVariable($Name, $PreviousEnvironment[$Name]) }
}
