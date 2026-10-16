#Requires -Version 7.4
<#
.SYNOPSIS
    Publishes an applied EntraOps update to Azure Repos as a pull request or by a direct push.

.DESCRIPTION
    Commits the applied update and rebases it onto the current head of the base branch.

    PullRequest (default) pushes the commit to the review branch entraops/update-<commit> and creates
    a pull request. While a pull request for this branch is active, the branch is left unchanged so
    commits added during the review are kept. A branch left from a completed or abandoned pull request
    is never overwritten; the update is then pushed to entraops/update-<commit>-<n>, so the Build
    Service needs no 'Force push' permission.

    DirectPush pushes the commit to the base branch without review; the updated pipeline definitions
    apply to the next runs. It needs only 'Contribute' (plus 'Bypass policies when pushing' for a
    branch protected by policies).

    The update pipeline copies this script and Ado-GitAuth.ps1 before the candidate is applied, so the
    job access token never reaches candidate code.
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
    [ValidateSet('PullRequest', 'DirectPush')]
    [string]$PublicationMode = 'PullRequest',

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
$TargetRef = "refs/heads/$BaseBranch"
# A leftover branch is never overwritten (that would need 'Force push'); the update then uses a
# numbered branch entraops/update-<commit>-<n>, so an active pull request can use any of these names.
$UpdateRefPattern = '^' + [regex]::Escape("refs/heads/$UpdateBranch") + '(-\d+)?$'
if ($PublicationMode -eq 'PullRequest') {
    $Query = "searchCriteria.targetRefName=$([uri]::EscapeDataString($TargetRef))&searchCriteria.status=active&`$top=1000&api-version=7.1"
    $Existing = @((Invoke-RestMethod -Method Get -Uri "$($PullRequestApi)?$Query" -Headers $Headers).value |
        Where-Object { $_ -and [string]$_.sourceRefName -match $UpdateRefPattern })
    if ($Existing.Count -gt 0) {
        Write-Host "Pull request $($Existing[0].pullRequestId) for '$($Existing[0].sourceRefName -replace '^refs/heads/', '')' is still active; its branch is left unchanged."
        return
    }
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

# The script block runs in a child scope; the selected branch is returned through this hashtable.
$Publication = @{ Branch = $null }
Invoke-EntraOpsAdoAuthenticatedGit -AccessToken $AccessToken -CollectionUri $CollectionUri -ScriptBlock {
    # Another pipeline may have committed since checkout; base the review branch on the current head
    & git fetch --no-tags origin "refs/heads/$BaseBranch"
    if ($LASTEXITCODE -ne 0) { throw "git fetch of '$BaseBranch' failed with exit code $LASTEXITCODE." }
    & git rebase FETCH_HEAD
    if ($LASTEXITCODE -ne 0) {
        & git rebase --abort 2>$null
        throw "git rebase onto the current '$BaseBranch' failed."
    }
    if ($PublicationMode -eq 'DirectPush') {
        & git push origin "HEAD:$TargetRef"
        if ($LASTEXITCODE -ne 0) { throw "Could not push the update to '$BaseBranch' (exit code $LASTEXITCODE). Grant the project Build Service 'Contribute' on the repository and 'Bypass policies when pushing' if the branch is protected by policies, or check whether the branch was changed concurrently." }
        return
    }
    # Branches left from completed or abandoned pull requests are kept; use the first free name.
    $MaximumBranchNumber = 50
    for ($Number = 1; $Number -le $MaximumBranchNumber -and -not $Publication.Branch; $Number++) {
        $Candidate = if ($Number -eq 1) { $UpdateBranch } else { "$UpdateBranch-$Number" }
        # git ls-remote --exit-code: 0 = branch exists, 2 = no matching ref, anything else = git/auth/network error.
        & git ls-remote --exit-code --heads origin "refs/heads/$Candidate" | Out-Null
        $LsRemoteExitCode = $LASTEXITCODE
        if ($LsRemoteExitCode -eq 2) {
            $Publication.Branch = $Candidate
        } elseif ($LsRemoteExitCode -ne 0) {
            throw "Could not query the remote for the update branch '$Candidate' (git ls-remote exit code $LsRemoteExitCode)."
        }
    }
    if (-not $Publication.Branch) {
        throw "The update branches '$UpdateBranch' to '$UpdateBranch-$MaximumBranchNumber' already exist. Delete the branches of completed or abandoned EntraOps update pull requests."
    }
    if ($Publication.Branch -ne $UpdateBranch) {
        Write-Host "Branch '$UpdateBranch' is left from a closed pull request and is kept; publishing to '$($Publication.Branch)'."
    }
    # A plain push never overwrites a branch created concurrently by another run.
    & git push origin "HEAD:refs/heads/$($Publication.Branch)"
    if ($LASTEXITCODE -ne 0) { throw "Could not push the new update branch '$($Publication.Branch)' (exit code $LASTEXITCODE). Grant the project Build Service 'Contribute' and 'Create branch' on the repository, or check whether the branch was created concurrently." }
}
if ($PublicationMode -eq 'DirectPush') {
    Write-Host "Pushed the update directly to '$BaseBranch' (PublicationMode DirectPush); no pull request is created."
    return
}
$UpdateBranch = $Publication.Branch
$SourceRef = "refs/heads/$UpdateBranch"

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
