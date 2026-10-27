#Requires -Version 7.4
<#
.SYNOPSIS
    Checks out the latest commit of the pipeline branch.

.DESCRIPTION
    A pipeline started by the completion of entraops-pull runs on the commit the pull run started from,
    which doesn't contain the data the pull run committed afterwards. This script fetches the current
    head of the branch and checks it out, so the push and reporting pipelines process the latest
    collected data. Runs that overlap with a later pull run process the data committed at fetch time.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$SourceBranch = $env:BUILD_SOURCEBRANCH,

    [Parameter(Mandatory = $false)]
    [string]$AccessToken = $env:SYSTEM_ACCESSTOKEN
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Ado-GitAuth.ps1')

$BranchName = Get-EntraOpsAdoBranchName -SourceBranch $SourceBranch
$CollectionUri = Get-EntraOpsAdoCollectionUri
$QueuedCommit = ([string](& git rev-parse HEAD)).Trim()

Invoke-EntraOpsAdoAuthenticatedGit -AccessToken $AccessToken -CollectionUri $CollectionUri -ScriptBlock {
    & git fetch --no-tags origin "refs/heads/$BranchName"
    if ($LASTEXITCODE -ne 0) { throw "git fetch of branch '$BranchName' failed with exit code $LASTEXITCODE." }
}
& git checkout --force --detach FETCH_HEAD
if ($LASTEXITCODE -ne 0) { throw "git checkout of the latest '$BranchName' commit failed with exit code $LASTEXITCODE." }

$LatestCommit = ([string](& git rev-parse HEAD)).Trim()
if ($LatestCommit -eq $QueuedCommit) {
    Write-Host "Commit $LatestCommit is already the latest commit of '$BranchName'."
} else {
    Write-Host "Checked out the latest commit $LatestCommit of '$BranchName' (run queued for $QueuedCommit)."
}
