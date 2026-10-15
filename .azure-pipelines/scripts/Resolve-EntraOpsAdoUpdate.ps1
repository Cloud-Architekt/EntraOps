#Requires -Version 7.4
<#
.SYNOPSIS
    Resolves the EntraOps update candidate for the Azure DevOps update pipeline without executing it.

.DESCRIPTION
    Clones the configured upstream ref, archives the immutable candidate for the credential-free
    validation job and sets the output variables of the update pipeline (source_sha, candidate_digest,
    update_required, validation_required, run_browser_tests). Validation frequency and browser tests
    are read from AutomatedEntraOpsUpdate in the configuration file. Azure DevOps always publishes an
    applied update as a pull request. When validation is required, stages the trusted deployment
    validators and the pipeline dependency installer for transfer to the validation job.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = './EntraOpsConfig.json',

    [Parameter(Mandatory = $false)]
    [string]$DestinationPath = './TmpUpdate',

    [Parameter(Mandatory = $false)]
    [string]$ArchivePath = (Join-Path ([string]$env:BUILD_ARTIFACTSTAGINGDIRECTORY) 'EntraOps-update-candidate.tar'),

    [Parameter(Mandatory = $false)]
    [string]$TrustedValidatorPath = (Join-Path ([string]$env:BUILD_ARTIFACTSTAGINGDIRECTORY) 'EntraOps-trusted-validators'),

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Ado-GitAuth.ps1')

function Set-EntraOpsAdoOutput {
    param ([string]$Name, [string]$Value)
    Write-Host "##vso[task.setvariable variable=$Name;isOutput=true]$Value"
}

$Config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json -Depth 20
$UpdateConfig = $Config.AutomatedEntraOpsUpdate
if ($UpdateConfig.ApplyAutomatedEntraOpsUpdate -ne $true) {
    Write-Host 'Automated EntraOps updates are disabled in the configuration.'
    Set-EntraOpsAdoOutput -Name 'update_required' -Value 'false'
    Set-EntraOpsAdoOutput -Name 'validation_required' -Value 'false'
    return
}

$ValidationFrequency = if ([string]::IsNullOrWhiteSpace([string]$UpdateConfig.ValidationFrequency)) { 'OnChange' } else { [string]$UpdateConfig.ValidationFrequency }
if ($ValidationFrequency -notin @('OnChange', 'Always', 'Never')) {
    throw "Unsupported AutomatedEntraOpsUpdate.ValidationFrequency '$ValidationFrequency'. Use OnChange, Always or Never."
}
$RunBrowserTests = $UpdateConfig.RunBrowserTests -ne $false
if ([string]$UpdateConfig.PublicationMode -eq 'DirectPush') {
    Write-Warning 'AutomatedEntraOpsUpdate.PublicationMode DirectPush is not supported by the Azure DevOps update pipeline; the update is published as a pull request.'
}

# An undefined EntraOpsUpdatePat variable arrives as the literal macro and must not be sent as a token
$PersonalAccessToken = Get-EntraOpsAdoSecretValue -Value $env:ENTRAOPS_PAT
if ([string]::IsNullOrWhiteSpace($PersonalAccessToken)) {
    Remove-Item -LiteralPath Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue
}

Import-Module (Join-Path $PSScriptRoot '../../EntraOps/EntraOps.psd1') -Force
$Candidate = Get-EntraOpsUpdateCandidate -ConfigFile $ConfigFile -DestinationPath $DestinationPath -ArchivePath $ArchivePath
$Decision = Get-EntraOpsUpdatePlan -Repository $Candidate.Repository -SourceCommit $Candidate.SourceCommit `
    -TargetUpdateFolders $Candidate.TargetUpdateFolders -ValidationFrequency $ValidationFrequency `
    -RunBrowserTests:$RunBrowserTests -Force:$Force

# The pipeline definitions run with the Azure service connection, so they are never applied unvalidated
if ($Candidate.TargetUpdateFolders -contains './.azure-pipelines' -and $Decision.UpdateRequired -and -not $Decision.ValidationRequired) {
    $Decision.ValidationRequired = $true
    $Decision.Reason = "$($Decision.Reason) Candidate validation is mandatory when Azure DevOps pipeline definitions are updated."
}
if ($Decision.ValidationRequired) {
    $TrustedScripts = Join-Path $PSScriptRoot '../../.github/scripts'
    $DependencyInstaller = Join-Path $PSScriptRoot 'Install-EntraOpsUpdateValidationDependencies.ps1'
    foreach ($RequiredScript in @(
            (Join-Path $TrustedScripts 'Test-EntraOpsUpdateCandidate.ps1')
            (Join-Path $TrustedScripts 'Test-GitHubActionReferences.ps1')
            $DependencyInstaller
        )) {
        if (-not (Test-Path -LiteralPath $RequiredScript -PathType Leaf)) {
            throw "Required trusted validation script '$RequiredScript' is missing. Restore it from the reviewed pipeline release before running the update. Keep './.github/scripts' and './.azure-pipelines' in AutomatedEntraOpsUpdate.TargetUpdateFolders."
        }
    }

    # The installer ships with the pipeline scripts, so older .github/scripts can still bootstrap validation.
    # Stage only trusted checkout files; candidate scripts must never replace the validation entry points.
    New-Item -ItemType Directory -Path $TrustedValidatorPath -Force | Out-Null
    Copy-Item -Path (Join-Path $TrustedScripts '*') -Destination $TrustedValidatorPath -Recurse -Force
    Copy-Item -LiteralPath $DependencyInstaller -Destination $TrustedValidatorPath -Force
}

Set-EntraOpsAdoOutput -Name 'source_sha' -Value $Candidate.SourceCommit
Set-EntraOpsAdoOutput -Name 'candidate_digest' -Value $Candidate.ArchiveSha256
Set-EntraOpsAdoOutput -Name 'update_required' -Value $Decision.UpdateRequired.ToString().ToLowerInvariant()
Set-EntraOpsAdoOutput -Name 'validation_required' -Value $Decision.ValidationRequired.ToString().ToLowerInvariant()
Set-EntraOpsAdoOutput -Name 'run_browser_tests' -Value $Decision.RunBrowserTests.ToString().ToLowerInvariant()
Write-Host "Resolved $($Candidate.Repository)@$($Candidate.SourceCommit). $($Decision.Reason) No candidate code was executed."
