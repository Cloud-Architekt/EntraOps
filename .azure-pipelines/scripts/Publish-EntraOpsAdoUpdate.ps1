#Requires -Version 7.4
<#
.SYNOPSIS
    Publishes an applied EntraOps update as an Azure Repos pull request.

.DESCRIPTION
    Commits the applied update, rebases it onto the current head of the base branch, pushes it to
    the review branch entraops/update-<commit> and creates a pull request. While a pull request for
    this branch is active, the branch is left unchanged so commits added during the review are kept;
    otherwise an existing branch is only replaced when it is still at the fetched commit. The update
    pipeline copies this script and Ado-GitAuth.ps1 before the candidate is applied, so the job access
    token never reaches candidate code.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$SourceCommit,

    [Parameter(Mandatory = $true)]
    [bool]$ValidationRequired,

    [Parameter(Mandatory = $true)]
    [bool]$BrowserTests,

    [Parameter(Mandatory = $false)]
    [string]$SourceBranch = $env:BUILD_SOURCEBRANCH,

    [Parameter(Mandatory = $false)]
    [string]$AccessToken = $env:SYSTEM_ACCESSTOKEN,

    [Parameter(Mandatory = $false)]
    [string]$ProjectId = $env:SYSTEM_TEAMPROJECTID,

    [Parameter(Mandatory = $false)]
    [string]$RepositoryId = $env:BUILD_REPOSITORY_ID,

    [Parameter(Mandatory = $false)]
    [string]$BuildId = $env:BUILD_BUILDID
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Ado-GitAuth.ps1')

if (Test-Path -LiteralPath './TmpUpdate') { throw 'The update candidate folder ./TmpUpdate still exists and must not be published.' }
if ([string]::IsNullOrWhiteSpace($AccessToken)) { throw 'The Azure DevOps job access token (System.AccessToken) is required to publish the update.' }
if ([string]::IsNullOrWhiteSpace($RepositoryId)) { throw 'Unable to determine the repository (BUILD_REPOSITORY_ID).' }

$BaseBranch = Get-EntraOpsAdoBranchName -SourceBranch $SourceBranch
$CollectionUri = Get-EntraOpsAdoCollectionUri
Assert-EntraOpsAdoProjectIsPrivate -AccessToken $AccessToken -CollectionUri $CollectionUri -ProjectId $ProjectId

$UpdateBranch = "entraops/update-$($SourceCommit.Substring(0, 12))"
$Headers = @{ Authorization = "Bearer $AccessToken" }
$PullRequestApi = "$CollectionUri/$ProjectId/_apis/git/repositories/$RepositoryId/pullrequests"
$SourceRef = "refs/heads/$UpdateBranch"
$TargetRef = "refs/heads/$BaseBranch"
$Query = "searchCriteria.sourceRefName=$([uri]::EscapeDataString($SourceRef))&searchCriteria.targetRefName=$([uri]::EscapeDataString($TargetRef))&searchCriteria.status=active&api-version=7.1"
$Existing = @((Invoke-RestMethod -Method Get -Uri "$($PullRequestApi)?$Query" -Headers $Headers).value | Where-Object { $_ })
if ($Existing.Count -gt 0) {
    Write-Host "Pull request $($Existing[0].pullRequestId) for '$UpdateBranch' is still active; its branch is left unchanged."
    return
}

& git config user.email 'entraops-ado@contoso.com'
if ($LASTEXITCODE -ne 0) { throw "git config user.email failed with exit code $LASTEXITCODE." }
& git config user.name 'Azure DevOps'
if ($LASTEXITCODE -ne 0) { throw "git config user.name failed with exit code $LASTEXITCODE." }
& git add --all -- .
if ($LASTEXITCODE -ne 0) { throw "git add failed with exit code $LASTEXITCODE." }
# git diff --quiet: 0 = no staged changes, 1 = staged changes, anything else = git error.
& git diff --cached --quiet
$DiffExitCode = $LASTEXITCODE
if ($DiffExitCode -eq 0) {
    Write-Host 'The applied update produced no changes; nothing to publish.'
    return
} elseif ($DiffExitCode -ne 1) {
    throw "git diff --cached failed with exit code $DiffExitCode."
}
& git commit -m "Update EntraOps to $SourceCommit"
if ($LASTEXITCODE -ne 0) { throw "git commit failed with exit code $LASTEXITCODE." }

Invoke-EntraOpsAdoAuthenticatedGit -AccessToken $AccessToken -CollectionUri $CollectionUri -ScriptBlock {
    # Another pipeline may have committed since checkout; base the review branch on the current head
    & git fetch --no-tags origin "refs/heads/$BaseBranch"
    if ($LASTEXITCODE -ne 0) { throw "git fetch of '$BaseBranch' failed with exit code $LASTEXITCODE." }
    & git rebase FETCH_HEAD
    if ($LASTEXITCODE -ne 0) {
        & git rebase --abort 2>$null
        throw "git rebase onto the current '$BaseBranch' failed."
    }
    # git ls-remote --exit-code: 0 = branch exists, 2 = no matching ref, anything else = git/auth/network error.
    # A missing branch produces no output; casting no output to [string] would yield $null
    $RemoteBranch = (@(& git ls-remote --exit-code --heads origin $SourceRef) -join "`n").Trim()
    $LsRemoteExitCode = $LASTEXITCODE
    if ($LsRemoteExitCode -eq 0) {
        # A branch left from a completed or abandoned pull request is replaced, unless it changed since this lookup
        $RemoteUpdateSha = ($RemoteBranch -split '\s+')[0]
        & git push "--force-with-lease=$($SourceRef):$RemoteUpdateSha" origin "HEAD:$SourceRef"
    } elseif ($LsRemoteExitCode -eq 2) {
        & git push origin "HEAD:$SourceRef"
    } else {
        throw "Could not query the remote for the update branch '$UpdateBranch' (git ls-remote exit code $LsRemoteExitCode)."
    }
    if ($LASTEXITCODE -ne 0) { throw "Could not push the update branch '$UpdateBranch' (exit code $LASTEXITCODE). Grant the project Build Service 'Contribute', 'Create branch' and 'Force push' on the repository, or check whether the branch was changed concurrently." }
}

$Validation = if ($ValidationRequired) {
    'The candidate passed the isolated validation job (Pester' + $(if ($BrowserTests) { ' and browser tests' } else { '' }) + ') without repository or Azure credentials.'
} else {
    'Candidate validation was not required for this run (AutomatedEntraOpsUpdate.ValidationFrequency); review the changes before merging.'
}
$RunUrl = if ($BuildId) { "$CollectionUri/$ProjectId/_build/results?buildId=$BuildId" } else { 'n/a' }
$PullRequest = [ordered]@{
    sourceRefName = $SourceRef
    targetRefName = $TargetRef
    title         = "Update EntraOps to $($SourceCommit.Substring(0, 12))"
    description   = "EntraOps update from source commit ``$SourceCommit``. $Validation Pipeline run: $RunUrl. Review the changes, in particular in .azure-pipelines, before merging."
}
try {
    $Created = Invoke-RestMethod -Method Post -Uri "$($PullRequestApi)?api-version=7.1" -Headers $Headers -ContentType 'application/json' -Body ($PullRequest | ConvertTo-Json)
} catch {
    throw "Pull request creation failed; the update branch '$UpdateBranch' was pushed. Grant the project Build Service 'Contribute to pull requests' on the repository. Error: $($_.Exception.Message)"
}
Write-Host "Created pull request $($Created.pullRequestId): $($Created.title)"
